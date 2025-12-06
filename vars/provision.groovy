import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.folders.FolderCredentialsProperty
import org.jenkinsci.plugins.plaincredentials.impl.*
import com.cloudbees.hudson.plugins.folder.*
import hudson.util.Secret

def call(Map config) {
    def projectName = config.projectName
    def environment = config.environment ?: 'dev'
    def createPostgres = config.postgres ?: false
    def secrets = config.secrets ?: []
    def pgHost = config.pgHost ?: 'postgres.tuempresa.com'
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
    def result = sh(
        script: """
            export PGPASSWORD='${adminPass}'
            psql -h ${host} -p ${port} -U ${adminUser} -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${targetUser}'" 2>/dev/null || echo ""
        """,
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
    sh """
        export PGPASSWORD='${adminPass}'
        
        # Crear usuario si no existe
        USER_EXISTS=\$(psql -h ${host} -p ${port} -U ${adminUser} -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${dbUser}'" 2>/dev/null || echo "")
        if [ "\$USER_EXISTS" != "1" ]; then
            echo "Creando usuario ${dbUser}..."
            psql -h ${host} -p ${port} -U ${adminUser} -d postgres -c "CREATE USER ${dbUser} WITH PASSWORD '${dbPass}';"
        fi
        
        # Crear base de datos si no existe
        DB_EXISTS=\$(psql -h ${host} -p ${port} -U ${adminUser} -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${dbName}'" 2>/dev/null || echo "")
        if [ "\$DB_EXISTS" != "1" ]; then
            echo "Creando base de datos ${dbName}..."
            psql -h ${host} -p ${port} -U ${adminUser} -d postgres -c "CREATE DATABASE ${dbName} OWNER ${dbUser};"
        fi
        
        # Crear schema si no existe
        SCHEMA_EXISTS=\$(psql -h ${host} -p ${port} -U ${adminUser} -d ${dbName} -tAc "SELECT 1 FROM information_schema.schemata WHERE schema_name='${dbSchema}'" 2>/dev/null || echo "")
        if [ "\$SCHEMA_EXISTS" != "1" ]; then
            echo "Creando schema ${dbSchema}..."
            psql -h ${host} -p ${port} -U ${adminUser} -d ${dbName} -c "CREATE SCHEMA ${dbSchema} AUTHORIZATION ${dbUser};"
        fi
        
        # Permisos
        psql -h ${host} -p ${port} -U ${adminUser} -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${dbUser};"
        psql -h ${host} -p ${port} -U ${adminUser} -d ${dbName} -c "GRANT ALL PRIVILEGES ON SCHEMA ${dbSchema} TO ${dbUser};"
        
        echo "PostgreSQL configurado correctamente"
    """
}

// ============================================
// FUNCIONES @NonCPS (Acceso directo a Jenkins API)
// ============================================

@NonCPS
def getCredentialsFromFolder(String folderPath, String credentialsId) {
    def folder = Jenkins.instance.getItemByFullName(folderPath)
    
    if (!(folder instanceof Folder)) {
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
def createUsernamePasswordSecret(String folderPath, String secretId, String username, String password) {
    def folder
    
    if (folderPath?.trim()) {
        folder = Jenkins.instance.getItemByFullName(folderPath)
    } else {
        def store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
        def credential = new UsernamePasswordCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned by Jenkins Shared Library",
            username,
            password
        )
        store.addCredentials(Domain.global(), credential)
        return
    }
    
    if (!(folder instanceof Folder)) {
        throw new Exception("Folder no encontrado: ${folderPath}")
    }
    
    def property = folder.properties.get(FolderCredentialsProperty)
    if (!property) {
        folder.addProperty(new FolderCredentialsProperty([]))
        property = folder.properties.get(FolderCredentialsProperty)
    }
    
    def store = property.store
    
    def existing = store.getCredentials(Domain.global()).find { it.id == secretId }
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
    def folder
    
    if (folderPath?.trim()) {
        folder = Jenkins.instance.getItemByFullName(folderPath)
    } else {
        def store = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
        def credential = new StringCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned by Jenkins Shared Library",
            Secret.fromString(value)
        )
        store.addCredentials(Domain.global(), credential)
        return
    }
    
    if (!(folder instanceof Folder)) {
        throw new Exception("Folder no encontrado: ${folderPath}")
    }
    
    def property = folder.properties.get(FolderCredentialsProperty)
    if (!property) {
        folder.addProperty(new FolderCredentialsProperty([]))
        property = folder.properties.get(FolderCredentialsProperty)
    }
    
    def store = property.store
    
    def existing = store.getCredentials(Domain.global()).find { it.id == secretId }
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
