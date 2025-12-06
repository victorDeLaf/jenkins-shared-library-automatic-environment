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
    def fullCredId = "${adminCredentialFolder}/${adminCredentialId}"

    if (createPostgres) {
        needsPostgres = !checkPostgresUserExistsSecure(fullCredId, pgHost, pgPort, dbUser)
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
        createPostgresResourcesSecure(fullCredId, pgHost, pgPort, dbUser, dbPass, dbName, dbSchema)
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

def checkPostgresUserExistsSecure(String credId, String host, String port, String targetUser) {
    def result = ""

    withCredentials([usernamePassword(credentialsId: credId, usernameVariable: 'PG_ADMIN_USER', passwordVariable: 'PG_ADMIN_PASS')]) {
        result = sh(
                script: """
                set +x
                export PGPASSWORD="\$PG_ADMIN_PASS"
                export TARGET_USER="${targetUser}"
                psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='\$TARGET_USER'" 2>/dev/null || echo ""
            """,
                returnStdout: true
        ).trim()
    }

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

def createPostgresResourcesSecure(String credId, String host, String port, String dbUser, String dbPass, String dbName, String dbSchema) {
    withCredentials([usernamePassword(credentialsId: credId, usernameVariable: 'PG_ADMIN_USER', passwordVariable: 'PG_ADMIN_PASS')]) {
        // Escribir contraseña del nuevo usuario a archivo temporal
        writeFile file: '.db_pass_temp', text: dbPass

        sh """
            set +x
            
            # Configurar .pgpass para el admin
            PGPASS_FILE=\$(mktemp)
            chmod 600 "\$PGPASS_FILE"
            echo "${host}:${port}:*:\$PG_ADMIN_USER:\$PG_ADMIN_PASS" > "\$PGPASS_FILE"
            export PGPASSFILE="\$PGPASS_FILE"
            
            # Leer contraseña del nuevo usuario desde archivo
            DB_PASS=\$(cat .db_pass_temp)
            
            # Variables para las queries
            export DB_USER="${dbUser}"
            export DB_NAME="${dbName}"
            export DB_SCHEMA="${dbSchema}"
            
            # Verificar y crear usuario
            USER_EXISTS=\$(psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='\$DB_USER'" 2>/dev/null || echo "")
            if [ "\$USER_EXISTS" != "1" ]; then
                echo "Creando usuario ${dbUser}..."
                psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -c "CREATE USER \$DB_USER WITH PASSWORD '\$DB_PASS';"
            fi
            
            # Verificar y crear base de datos
            DB_EXISTS=\$(psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='\$DB_NAME'" 2>/dev/null || echo "")
            if [ "\$DB_EXISTS" != "1" ]; then
                echo "Creando base de datos ${dbName}..."
                psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -c "CREATE DATABASE \$DB_NAME OWNER \$DB_USER;"
            fi
            
            # Verificar y crear schema
            SCHEMA_EXISTS=\$(psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d "\$DB_NAME" -tAc "SELECT 1 FROM information_schema.schemata WHERE schema_name='\$DB_SCHEMA'" 2>/dev/null || echo "")
            if [ "\$SCHEMA_EXISTS" != "1" ]; then
                echo "Creando schema ${dbSchema}..."
                psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d "\$DB_NAME" -c "CREATE SCHEMA \$DB_SCHEMA AUTHORIZATION \$DB_USER;"
            fi
            
            # Asignar permisos
            psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE \$DB_NAME TO \$DB_USER;"
            psql -h ${host} -p ${port} -U "\$PG_ADMIN_USER" -d "\$DB_NAME" -c "GRANT ALL PRIVILEGES ON SCHEMA \$DB_SCHEMA TO \$DB_USER;"
            
            # Limpiar
            rm -f "\$PGPASS_FILE"
            
            echo "PostgreSQL configurado correctamente"
        """

        // Limpiar archivo de contraseña
        sh "rm -f .db_pass_temp"
    }
}

// ============================================
// FUNCIONES @NonCPS (Acceso directo a Jenkins API)
// ============================================

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