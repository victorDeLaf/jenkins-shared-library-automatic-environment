# Referencia Técnica - Auto Provisioning

## Qué es

Shared library `jenkins-shared-library` que auto-crea:
- Secretos en el folder del proyecto
- Usuario PostgreSQL
- Base de datos PostgreSQL

## Prerequisitos

- Shared library `jenkins-shared-library` configurada en Jenkins (Global Trusted Pipeline Libraries)
- Folder `_admin` en Jenkins con credencial `postgres-admin-credentials` (Username with password del admin de PostgreSQL)

## Agregar a Jenkinsfile

```groovy
@Library('jenkins-shared-library') _

def CONFIG = [
    projectName: 'NOMBRE_PROYECTO',
    environment: 'dev',
    postgres: true,
    pgHost: 'HOST_POSTGRES',
    pgPort: '5432',
    adminCredentialFolder: '_admin',
    adminCredentialId: 'postgres-admin-credentials',
    secrets: ['db-credentials', 'db-url']
]

pipeline {
    agent any
    
    stages {
        stage('Provision') {
            steps {
                provision(CONFIG)
            }
        }
        
        stage('Deploy') {
            steps {
                withCredentials([
                    usernamePassword(credentialsId: 'db-credentials', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS'),
                    string(credentialsId: 'db-url', variable: 'DATABASE_URL')
                ]) {
                    // tu código aquí
                }
            }
        }
    }
}
```

## CONFIG - Opciones

| Opción | Requerido | Default | Qué es |
|--------|-----------|---------|--------|
| projectName | Sí | - | Nombre del proyecto |
| environment | No | dev | dev / staging / prod |
| postgres | No | false | Crear BD y usuario |
| pgHost | No | postgres.tuempresa.com | Host PostgreSQL |
| pgPort | No | 5432 | Puerto PostgreSQL |
| adminCredentialFolder | No | _admin | Folder con cred admin |
| adminCredentialId | No | postgres-admin-credentials | ID cred admin |
| secrets | No | [] | Lista de secretos |

## Secretos disponibles

| ID | Tipo | Genera |
|----|------|--------|
| db-credentials | usernamePassword | usuario + password |
| db-url | string | postgresql://user:pass@host:port/db |
| db-host | string | host |
| db-port | string | puerto |
| db-name | string | nombre BD |
| db-user | string | nombre usuario |
| (otro) | string | aleatorio 32 chars |

## Nomenclatura auto

```
projectName + environment = nombre BD y usuario

mi-api + dev = mi_api_dev
mi-api + prod = mi_api_prod
```

## Ejemplos

### Solo BD

```groovy
def CONFIG = [
    projectName: 'mi-api',
    postgres: true,
    pgHost: 'postgres.empresa.com',
    secrets: ['db-credentials', 'db-url']
]
```

### Solo secretos

```groovy
def CONFIG = [
    projectName: 'mi-frontend',
    postgres: false,
    secrets: ['api-key', 'jwt-secret']
]
```

### Producción

```groovy
def CONFIG = [
    projectName: 'mi-api',
    environment: 'prod',
    postgres: true,
    pgHost: 'postgres-prod.empresa.com',
    secrets: ['db-credentials', 'db-url', 'jwt-secret']
]
```

### Por rama

```groovy
def ENV = env.BRANCH_NAME == 'main' ? 'prod' : 'dev'
def HOST = env.BRANCH_NAME == 'main' ? 'pg-prod.com' : 'pg-dev.com'

def CONFIG = [
    projectName: 'mi-api',
    environment: ENV,
    pgHost: HOST,
    postgres: true,
    secrets: ['db-credentials', 'db-url']
]
```

## Usar secretos después

```groovy
// Username + Password
withCredentials([
    usernamePassword(credentialsId: 'db-credentials', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS')
]) {
    sh 'echo $DB_USER'
}

// String
withCredentials([
    string(credentialsId: 'db-url', variable: 'DATABASE_URL')
]) {
    sh 'echo $DATABASE_URL'
}

// Múltiples
withCredentials([
    usernamePassword(credentialsId: 'db-credentials', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS'),
    string(credentialsId: 'db-url', variable: 'DATABASE_URL'),
    string(credentialsId: 'jwt-secret', variable: 'JWT_SECRET')
]) {
    sh './deploy.sh'
}
```
