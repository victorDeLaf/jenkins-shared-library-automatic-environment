def call(Map config) {
    def projectName = config.projectName
    def environment = config.environment ?: 'dev'
    def createPostgres = config.postgres ?: false
    def secrets = config.secrets ?: []
    def pgHost = config.pgHost ?: 'postgres.tuempresa.com'
    
    def safeProjectName = projectName.toLowerCase().replaceAll('[^a-z0-9]', '_')
    def folderPath = env.JOB_NAME.substring(0, env.JOB_NAME.lastIndexOf('/'))
    
    def dbUser = "${safeProjectName}_${environment}"
    def dbName = "${safeProjectName}_${environment}"
    
    echo "=== Auto-Provisioning ==="
    echo "Proyecto: ${projectName}"
    echo "Folder: ${folderPath}"
    echo "PostgreSQL: ${createPostgres}"
    echo "Secretos: ${secrets}"
    
    // Verificar qué existe y qué falta
    def missingSecrets = []
    secrets.each { secretId ->
        if (!secretExists(secretId)) {
            missingSecrets.add(secretId)
        }
    }
    
    def needsPostgres = false
    if (createPostgres) {
        needsPostgres = !postgresUserExists(pgHost, dbUser)
    }
    
    // Si todo existe, continuar
    if (missingSecrets.isEmpty() && !needsPostgres) {
        echo "✓ Todo existe, continuando..."
        return
    }
    
    // Generar password si necesitamos crear algo de postgres
    def dbPass = ""
    if (needsPostgres || missingSecrets.contains('db-credentials') || missingSecrets.contains('db-url')) {
        dbPass = generatePassword()
    }
    
    // Crear PostgreSQL si es necesario
    if (needsPostgres) {
        echo "Creando usuario y BD en PostgreSQL..."
        createPostgresResources(pgHost, dbUser, dbPass, dbName)
    }
    
    // Crear secretos faltantes
    missingSecrets.each { secretId ->
        echo "Creando secreto: ${secretId}"
        def value = generateSecretValue(secretId, dbUser, dbPass, dbName, pgHost)
        createFolderSecret(folderPath, secretId, value)
    }
    
    echo "✓ Provisioning completado"
}

def generatePassword() {
    return sh(script: "openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24", returnStdout: true).trim()
}

def secretExists(String secretId) {
    try {
        withCredentials([string(credentialsId: secretId, variable: 'TEST')]) {
            return true
        }
    } catch (Exception e) {
        try {
            withCredentials([usernamePassword(credentialsId: secretId, usernameVariable: 'U', passwordVariable: 'P')]) {
                return true
            }
        } catch (Exception e2) {
            return false
        }
    }
}

def postgresUserExists(String pgHost, String dbUser) {
    def result = false
    withCredentials([usernamePassword(credentialsId: 'postgres-admin-credentials', usernameVariable: 'PG_USER', passwordVariable: 'PG_PASS')]) {
        def output = sh(script: """
            export PGPASSWORD='${PG_PASS}'
            psql -h ${pgHost} -U ${PG_USER} -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='${dbUser}'" || echo ""
        """, returnStdout: true).trim()
        result = output == "1"
    }
    return result
}

def createPostgresResources(String pgHost, String dbUser, String dbPass, String dbName) {
    withCredentials([usernamePassword(credentialsId: 'postgres-admin-credentials', usernameVariable: 'PG_USER', passwordVariable: 'PG_PASS')]) {
        sh """
            export PGPASSWORD='${PG_PASS}'
            
            # Crear usuario
            psql -h ${pgHost} -U ${PG_USER} -d postgres -c "CREATE USER ${dbUser} WITH PASSWORD '${dbPass}';"
            
            # Crear BD
            psql -h ${pgHost} -U ${PG_USER} -d postgres -c "CREATE DATABASE ${dbName} OWNER ${dbUser};"
            
            # Permisos
            psql -h ${pgHost} -U ${PG_USER} -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${dbUser};"
        """
    }
}

def generateSecretValue(String secretId, String dbUser, String dbPass, String dbName, String pgHost) {
    switch(secretId) {
        case 'db-credentials':
            return [type: 'usernamePassword', username: dbUser, password: dbPass]
        case 'db-url':
            return [type: 'text', value: "postgresql://${dbUser}:${dbPass}@${pgHost}:5432/${dbName}"]
        case 'db-host':
            return [type: 'text', value: pgHost]
        case 'db-name':
            return [type: 'text', value: dbName]
        default:
            // Para cualquier otro secreto, generar valor aleatorio
            return [type: 'text', value: sh(script: "openssl rand -base64 32", returnStdout: true).trim()]
    }
}

@NonCPS
def createFolderSecret(String folderPath, String secretId, Map secretData) {
    import com.cloudbees.plugins.credentials.*
    import com.cloudbees.plugins.credentials.domains.*
    import com.cloudbees.plugins.credentials.impl.*
    import org.jenkinsci.plugins.plaincredentials.impl.*
    import com.cloudbees.hudson.plugins.folder.*
    import com.cloudbees.hudson.plugins.folder.properties.*
    import hudson.util.Secret
    
    def folder = Jenkins.instance.getItemByFullName(folderPath)
    
    if (!(folder instanceof Folder)) {
        error("Folder no encontrado: ${folderPath}")
    }
    
    def folderStore = folder.properties.get(FolderCredentialsProperty)
    if (!folderStore) {
        folder.addProperty(new FolderCredentialsProperty([]))
        folderStore = folder.properties.get(FolderCredentialsProperty)
    }
    
    def store = folderStore.store
    
    def newCred
    if (secretData.type == 'usernamePassword') {
        newCred = new UsernamePasswordCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned",
            secretData.username,
            secretData.password
        )
    } else {
        newCred = new StringCredentialsImpl(
            CredentialsScope.GLOBAL,
            secretId,
            "Auto-provisioned",
            Secret.fromString(secretData.value)
        )
    }
    
    store.addCredentials(Domain.global(), newCred)
}
