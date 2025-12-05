# Jenkins Shared Library - Auto Provisioning

Librería para crear automáticamente secretos, usuarios y bases de datos PostgreSQL cuando se ejecuta un pipeline.

## Prerequisitos

1. **Credencial de PostgreSQL admin** configurada en Jenkins:
   - ID: `postgres-admin-credentials`
   - Tipo: Username with password
   - Usuario con permisos para CREATE USER, CREATE DATABASE, GRANT

2. **Plugins de Jenkins:**
   - credentials
   - credentials-binding
   - cloudbees-folder
   - plain-credentials

3. **Cliente psql** instalado en el agente de Jenkins

## Instalación

1. Configura esta librería en **Manage Jenkins → System → Global Pipeline Libraries**
2. La primera ejecución requerirá aprobar scripts en **Manage Jenkins → In-process Script Approval**

## Uso
```groovy
@Library('jenkins-shared-library') _

def CONFIG = [
    projectName: 'mi-api',
    environment: 'dev',
    postgres: true,
    secrets: ['db-credentials', 'db-url', 'jwt-secret']
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
                    usernamePassword(credentialsId: 'db-credentials', usernameVariable: 'DB_USER', passwordVariable: 'DB_PASS')
                ]) {
                    sh './deploy.sh'
                }
            }
        }
    }
}
```

## Opciones de configuración

| Opción | Tipo | Requerido | Default | Descripción |
|--------|------|-----------|---------|-------------|
| `projectName` | String | Sí | - | Nombre del proyecto (se usa para nombrar BD y usuario) |
| `environment` | String | No | `dev` | Ambiente (dev, staging, prod) |
| `postgres` | Boolean | No | `false` | Crear usuario y BD en PostgreSQL |
| `secrets` | List | No | `[]` | Lista de secretos a crear |
| `pgHost` | String | No | `postgres.tuempresa.com` | Host de PostgreSQL |

## Secretos disponibles

| Nombre | Tipo | Valor generado |
|--------|------|----------------|
| `db-credentials` | usernamePassword | Usuario y password de PostgreSQL |
| `db-url` | text | `postgresql://user:pass@host:5432/dbname` |
| `db-host` | text | Host de PostgreSQL |
| `db-name` | text | Nombre de la base de datos |
| (cualquier otro) | text | String aleatorio de 32 caracteres |

## Ejemplos

### Solo PostgreSQL
```groovy
def CONFIG = [
    projectName: 'api-usuarios',
    postgres: true,
    secrets: ['db-credentials', 'db-url']
]
```

### Solo secretos (sin BD)
```groovy
def CONFIG = [
    projectName: 'frontend-web',
    postgres: false,
    secrets: ['api-key', 'analytics-token']
]
```

### Ambiente producción
```groovy
def CONFIG = [
    projectName: 'api-pagos',
    environment: 'prod',
    postgres: true,
    pgHost: 'postgres-prod.tuempresa.com',
    secrets: ['db-credentials', 'db-url', 'stripe-key']
]
```

## Comportamiento

- Si el secreto ya existe → no hace nada
- Si el usuario PostgreSQL ya existe → no hace nada
- Si la BD ya existe → no hace nada
- Los secretos se crean en el **folder del pipeline que ejecuta**

## Notas

- Los passwords se generan con `openssl rand` (24 caracteres alfanuméricos)
- El nombre de usuario y BD se deriva de: `{projectName}_{environment}`
- Caracteres especiales en `projectName` se reemplazan por `_`
