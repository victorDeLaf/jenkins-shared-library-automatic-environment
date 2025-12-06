import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.plugins.credentials.common.*
import org.jenkinsci.plugins.plaincredentials.impl.*
import com.cloudbees.hudson.plugins.folder.*
import hudson.util.Secret

def call(Map config) {
    def projectName = config.projectName
    def environment = config.environment ?: 'dev'
    def createPostgres = config.postgres ?: false
    def secrets = config.secrets ?: []
    def pgHost = config.pgHost ?: 'localhost'
    def pgPort = config.pgPort ?: '5432'
    def adminCredentialFolder = config.adminCredentialFolder ?: '_admin'
    def adminCredentialId = config.adminCredentialId ?: 'postgres-admin-credentials'

    def safeProjectName = projectName.toLowerCase().replaceAll('[^a-z0-9]', '_')
    def folderPath = env.JOB_NAME.contains('/') ? env.JOB_NAME.substring(0, env.JOB_NAME.lastIndexOf('/')) : ''

    def dbUser = "${safeProjectName}_${environment}"
    def dbName = "${safeProjectName}_${environment}"
    def dbSchema = config.pgSchema ?: "${safeProjectName}_${environment}"

    echo "============================================"
    echo "AUTO-PROVISIONING"
    echo "============================================"
    echo "Proyecto:    ${projectName}"
    echo "Ambiente:    ${environment}"
    echo "Folder:      ${folderPath ?: 'root'}"
    echo "PostgreSQL:  ${createPostgres}"
    echo "Schema:      ${dbSchema}"
    echo "Secretos:    ${secrets}"
    echo "============================================"

    // Verificar qué secretos faltan
    def missingSecrets = []
    secrets.each { secretId ->
        if (!checkSecretExists(secretId)) {
            missingSecrets.add(secretId)
            echo "✗ Secreto '${secretId}' no existe"
        } else {
            echo "✓ Secreto '${secretId}' ya existe"
        }
    }

    // Verificar si PostgreSQL necesita crearse
    def needsPostgres = false
    if (createPostgres) {
        def adminCreds = getCredentialsFromFolder(adminCredentialFolder, adminCredentialId)
        if (!adminCreds) {
            error "No se encontró la credencial '${adminCredentialId}' en el folder '${adminCredentialFolder}'"
        }
        needsPostgres = !checkPostgresUserExists(pgHost, pgPort, adminCreds.username, adminCreds.password, dbUser)
        if (needsPostgres) {
            echo "✗ Usuario PostgreSQL '${dbUser}' no existe"
        } else {
            echo "✓ Usuario PostgreSQL '${dbUser}' ya existe"
        }
    }

    // Si todo existe, terminar
    if (missingSecrets.isEmpty() && !needsPostgres) {
        echo "============================================"
        echo "✓ Todo existe, nada que provisionar"
        echo "============================================"
        return
    }

    echo "============================================"
    echo "Iniciando provisioning..."
    echo "============================================"

    // Generar password para BD
    def dbPass = ""
    def needsDbPassword = needsPostgres ||
            missingSecrets.contains('db-credentials') ||
            missingSecrets.contains('db-url')

    if (needsDbPassword) {
        dbPass = generateSecurePassword()
    }

    // Crear PostgreSQL si es necesario
    if (needsPostgres) {
        echo "Creando usuario, base de datos y schema en PostgreSQL..."
        def adminCreds = getCredentialsFromFolder(adminCredentialFolder, adminCredentialId)
        createPostgresResources(pgHost, pgPort, adminCreds.username, adminCreds.password, dbUser, dbPass, dbName, dbSchema)
        echo "✓ PostgreSQL configurado"
    }

    // Crear secretos faltantes
    if (!missingSecrets.isEmpty()) {
        echo "Creando secretos en folder '${folderPath ?: 'root'}'..."

        missingSecrets.each { secretId ->
            def secretValue = generateSecretValue(secretId, dbUser, dbPass, dbName, dbSchema, pgHost, pgPort)

            if (secretValue.type == 'usernamePassword') {
                createUsernamePasswordSecret(folderPath, secretId, secretValue.username, secretValue.password)
            } else {
                createTextSecret(folderPath, secretId, secretValue.value)
            }

            echo "✓ Secreto '${secretId}' creado"
        }
    }

    echo "============================================"
    echo "✓ PROVISIONING COMPLETADO"
    echo "============================================"
}

// ============================================
// FUNCIONES DE VERIFICACIÓN
// ============================================

def checkSecretExists(String secretId) {
    try {
        withCredentials([string(credentialsId: secretId, variable: 'TEST')]) {
            return true
        }
    } catch (Exception e1) {
        try {
            withCredentials([usernamePassword(credentialsId: secretId, usernameVariable: 'U', passwordVariable: 'P')]) {
                return true
            }
        } catch (Exception e2) {
            return false
        }
    }
}

def checkPostgresUserExists(String host, String port, String adminUser, String adminPass, String targetUser) {
    // Escribir credenciales a archivos temporales
    writeFile file: '.pgadmin_user', text: adminUser
    writeFile file: '.pgadmin_pass', text: adminPass
    writeFile file: '.pgtarget_user', text: targetUser

    def result = sh(
            script: '''#!/bin/bash
            set +x
            PG_USER=$(cat .pgadmin_user)
            PG_PASS=$(cat .pgadmin_pass)
            TARGET=$(cat .pgtarget_user)
            rm -f .pgadmin_user .pgadmin_pass .pgtarget_user
            
            export PGPASSWORD="$PG_PASS"
            psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$TARGET'" 2>/dev/null || echo ""
        ''',
            returnStdout: true
    ).trim()

    return result == "1"
}

// ============================================
// FUNCIONES DE CREACIÓN
// ============================================

def generateSecurePassword() {
    return sh(
            script: "openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24",
            returnStdout: true
    ).trim()
}

def generateSecretValue(String secretId, String dbUser, String dbPass, String dbName, String dbSchema, String pgHost, String pgPort) {
    switch(secretId) {
        case 'db-credentials':
            return [type: 'usernamePassword', username: dbUser, password: dbPass]
        case 'db-url':
            return [type: 'text', value: "postgresql://${dbUser}:${dbPass}@${pgHost}:${pgPort}/${dbName}"]
        case 'db-host':
            return [type: 'text', value: pgHost]
        case 'db-port':
            return [type: 'text', value: pgPort]
        case 'db-name':
            return [type: 'text', value: dbName]
        case 'db-user':
            return [type: 'text', value: dbUser]
        case 'db-schema':
            return [type: 'text', value: dbSchema]
        default:
            def randomValue = sh(
                    script: "openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 32",
                    returnStdout: true
            ).trim()
            return [type: 'text', value: randomValue]
    }
}

def createPostgresResources(String host, String port, String adminUser, String adminPass, String dbUser, String dbPass, String dbName, String dbSchema) {
    // Escribir todas las credenciales a archivos temporales
    writeFile file: '.pgadmin_user', text: adminUser
    writeFile file: '.pgadmin_pass', text: adminPass
    writeFile file: '.newdb_user', text: dbUser
    writeFile file: '.newdb_pass', text: dbPass
    writeFile file: '.newdb_name', text: dbName
    writeFile file: '.newdb_schema', text: dbSchema

    sh '''#!/bin/bash
        set +x
        
        # Leer credenciales de archivos
        PG_ADMIN_USER=$(cat .pgadmin_user)
        PG_ADMIN_PASS=$(cat .pgadmin_pass)
        DB_USER=$(cat .newdb_user)
        DB_PASS=$(cat .newdb_pass)
        DB_NAME=$(cat .newdb_name)
        DB_SCHEMA=$(cat .newdb_schema)
        
        # Limpiar archivos de credenciales inmediatamente
        rm -f .pgadmin_user .pgadmin_pass .newdb_user .newdb_pass .newdb_name .newdb_schema
        
        # Configurar .pgpass temporal
        PGPASS_FILE=$(mktemp)
        chmod 600 "$PGPASS_FILE"
        echo "''' + host + ''':''' + port + ''':*:$PG_ADMIN_USER:$PG_ADMIN_PASS" > "$PGPASS_FILE"
        export PGPASSFILE="$PGPASS_FILE"
        
        # Verificar y crear usuario
        USER_EXISTS=$(psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null || echo "")
        if [ "$USER_EXISTS" != "1" ]; then
            echo "Creando usuario $DB_USER..."
            psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d postgres -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
        fi
        
        # Verificar y crear base de datos
        DB_EXISTS=$(psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || echo "")
        if [ "$DB_EXISTS" != "1" ]; then
            echo "Creando base de datos $DB_NAME..."
            psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
        fi
        
        # Verificar y crear schema
        SCHEMA_EXISTS=$(psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d "$DB_NAME" -tAc "SELECT 1 FROM information_schema.schemata WHERE schema_name='$DB_SCHEMA'" 2>/dev/null || echo "")
        if [ "$SCHEMA_EXISTS" != "1" ]; then
            echo "Creando schema $DB_SCHEMA..."
            psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d "$DB_NAME" -c "CREATE SCHEMA $DB_SCHEMA AUTHORIZATION $DB_USER;"
        fi
        
        # Asignar permisos
        psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
        psql -h ''' + host + ''' -p ''' + port + ''' -U "$PG_ADMIN_USER" -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON SCHEMA $DB_SCHEMA TO $DB_USER;"
        
        # Limpiar archivo pgpass
        rm -f "$PGPASS_FILE"
        
        echo "PostgreSQL configurado correctamente"
    '''
}

// ============================================
// FUNCIONES @NonCPS (Acceso directo a Jenkins API)
// ============================================

@NonCPS
def getCredentialsFromFolder(String folderPath, String credentialsId) {
    def folder = Jenkins.instance.getItemByFullName(folderPath)

    if (!folder) {
        return null
    }

    def credentials = CredentialsProvider.lookupCredentials(
            StandardUsernamePasswordCredentials.class,
            folder,
            null,
            []
    ).find { it.id == credentialsId }

    if (credentials) {
        return [
                username: credentials.username,
                password: credentials.password.plainText
        ]
    }

    return null
}

@NonCPS
def getCredentialsStore(def item) {
    def stores = CredentialsProvider.lookupStores(item)
    for (store in stores) {
        if (store.getContext() == item) {
            return store
        }
    }
    return stores.find { true }
}

@NonCPS
def createUsernamePasswordSecret(String folderPath, String secretId, String username, String password) {
    def item
    def store

    if (folderPath?.trim()) {
        item = Jenkins.instance.getItemByFullName(folderPath)
        if (!item) {
            throw new Exception("Folder no encontrado: ${folderPath}")
        }
        store = getCredentialsStore(item)
    } else {
        store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    }

    if (!store) {
        throw new Exception("No se pudo obtener el credentials store")
    }

    // Eliminar si ya existe
    def existing = CredentialsProvider.lookupCredentials(
            StandardUsernamePasswordCredentials.class,
            item ?: Jenkins.instance,
            null,
            []
    ).find { it.id == secretId }

    if (existing) {
        store.removeCredentials(Domain.global(), existing)
    }

    def credential = new UsernamePasswordCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned by Jenkins Shared Library",
            username,
            password
    )

    store.addCredentials(Domain.global(), credential)
}

@NonCPS
def createTextSecret(String folderPath, String secretId, String value) {
    def item
    def store

    if (folderPath?.trim()) {
        item = Jenkins.instance.getItemByFullName(folderPath)
        if (!item) {
            throw new Exception("Folder no encontrado: ${folderPath}")
        }
        store = getCredentialsStore(item)
    } else {
        store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    }

    if (!store) {
        throw new Exception("No se pudo obtener el credentials store")
    }

    // Eliminar si ya existe
    def existing = CredentialsProvider.lookupCredentials(
            com.cloudbees.plugins.credentials.common.StandardCredentials.class,
            item ?: Jenkins.instance,
            null,
            []
    ).find { it.id == secretId }

    if (existing) {
        store.removeCredentials(Domain.global(), existing)
    }

    def credential = new StringCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned by Jenkins Shared Library",
            Secret.fromString(value)
    )

    store.addCredentials(Domain.global(), credential)
}