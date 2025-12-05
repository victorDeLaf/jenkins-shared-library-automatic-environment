# Jenkins Shared Library - Auto Provisioning

Librería compartida de Jenkins que crea automáticamente secretos, usuarios y bases de datos PostgreSQL cuando se ejecuta un pipeline.

## Qué hace

Cada vez que un pipeline se ejecuta:

1. Verifica si los secretos ya existen en el folder del proyecto
2. Verifica si el usuario y base de datos PostgreSQL ya existen
3. Si falta algo, lo crea automáticamente
4. Si todo existe, continúa sin hacer nada

## Estructura del repositorio

```
jenkins-shared-library/
├── README.md
└── vars/
    └── provision.groovy
```

## Prerequisitos

### Plugins de Jenkins

- credentials
- credentials-binding
- cloudbees-folder
- plain-credentials

### Cliente PostgreSQL

El agente de Jenkins debe tener instalado psql:

```bash
# Ubuntu/Debian
apt-get install postgresql-client

# CentOS/RHEL
yum install postgresql

# Alpine
apk add postgresql-client
```

### Folder de administración con credenciales

Crear un folder _admin en Jenkins con la credencial del usuario admin de PostgreSQL:

1. Crear folder:
   - Jenkins → New Item → Nombre: _admin → Tipo: Folder → OK

2. Crear credencial dentro del folder:
   - Entrar al folder _admin
   - Click en Credentials (panel izquierdo)
   - Click en (global) bajo "Stores scoped to _admin"
   - Add Credentials:
     - Kind: Username with password
     - Username: usuario admin de PostgreSQL
     - Password: password admin de PostgreSQL
     - ID: postgres-admin-credentials
     - Description: Credenciales admin PostgreSQL
   - Click Create

Nota: El usuario de PostgreSQL debe tener permisos para CREATE USER, CREATE DATABASE y GRANT.

## Instalación

### 1. Crear el repositorio

Crea un repositorio Git con la estructura indicada arriba.

### 2. Configurar en Jenkins

1. Ve a Manage Jenkins → System
2. Busca la sección Global Pipeline Libraries
3. Click Add
4. Configura:
   - Name: jenkins-shared-library
   - Default version: main
   - Allow default version to be overridden: marcado
   - Load implicitly: desmarcado
   - Retrieval method: Modern SCM → Git
   - Project Repository: URL de tu repositorio
   - Credentials: (si el repo es privado)
5. Click Save

### 3. Aprobar scripts

La primera ejecución fallará porque Jenkins necesita aprobar los scripts:

1. Ejecuta un pipeline que use la librería
2. Ve a Manage Jenkins → In-process Script Approval
3. Aprueba todos los scripts pendientes
4. Vuelve a ejecutar

## Uso

### Ejemplo básico

```groovy
@Library('jenkins-shared-library') _

def CONFIG = [
    projectName: 'mi-api',
    postgres: true,
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
                    sh './deploy.sh'
                }
            }
        }
    }
}
```

### Ejemplo completo

```groovy
@Library('jenkins-shared-library') _

def CONFIG = [
    projectName: 'mi-api',
    environment: 'prod',
    postgres: true,
    pgHost: 'postgres-prod.tuempresa.com',
    pgPort: '5432',
    adminCredentialFolder: '_admin',
    adminCredentialId: 'postgres-admin-credentials',
    secrets: ['db-credentials', 'db-url', 'jwt-secret', 'api-key']
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
                    string(credentialsId: 'db-url', variable: 'DATABASE_URL'),
                    string(credentialsId: 'jwt-secret', variable: 'JWT_SECRET')
                ]) {
                    sh './deploy.sh'
                }
            }
        }
    }
}
```

### Solo secretos (sin PostgreSQL)

```groovy
@Library('jenkins-shared-library') _

def CONFIG = [
    projectName: 'mi-frontend',
    postgres: false,
    secrets: ['api-key', 'analytics-token']
]

pipeline {
    agent any
    
    stages {
        stage('Provision') {
            steps {
                provision(CONFIG)
            }
        }
        
        stage('Build') {
            steps {
                withCredentials([
                    string(credentialsId: 'api-key', variable: 'API_KEY')
                ]) {
                    sh 'npm run build'
                }
            }
        }
    }
}
```

## Opciones de configuración

| Opción | Tipo | Requerido | Default | Descripción |
|--------|------|-----------|---------|-------------|
| projectName | String | Sí | - | Nombre del proyecto |
| environment | String | No | dev | Ambiente (dev, staging, prod) |
| postgres | Boolean | No | false | Crear usuario y BD en PostgreSQL |
| pgHost | String | No | postgres.tuempresa.com | Host de PostgreSQL |
| pgPort | String | No | 5432 | Puerto de PostgreSQL |
| adminCredentialFolder | String | No | _admin | Folder con credencial admin |
| adminCredentialId | String | No | postgres-admin-credentials | ID de credencial admin |
| secrets | List | No | [] | Lista de secretos a crear |

## Secretos disponibles

| Nombre | Tipo | Valor generado |
|--------|------|----------------|
| db-credentials | Username/Password | Usuario y password de PostgreSQL |
| db-url | Text | postgresql://user:pass@host:port/dbname |
| db-host | Text | Host del servidor |
| db-port | Text | Puerto del servidor |
| db-name | Text | Nombre de la base de datos |
| db-user | Text | Nombre del usuario |
| (cualquier otro) | Text | String aleatorio de 32 caracteres |

## Nomenclatura automática

| projectName | environment | Usuario/BD PostgreSQL |
|-------------|-------------|----------------------|
| mi-api | dev | mi_api_dev |
| mi-api | prod | mi_api_prod |
| user-service | staging | user_service_staging |

## Dónde se crean los secretos

Los secretos se crean en el folder del job que ejecuta el pipeline.

Ejemplo:
- Job: equipo-backend/mi-api/main
- Folder: equipo-backend/mi-api
- Secretos se crean en: equipo-backend/mi-api

## Troubleshooting

### Error: No se encontró la credencial

- Verificar que el folder _admin existe
- Verificar que la credencial postgres-admin-credentials está dentro
- Verificar que el ID es exactamente postgres-admin-credentials

### Error: Scripts not approved

1. Ir a Manage Jenkins → In-process Script Approval
2. Aprobar scripts pendientes
3. Volver a ejecutar

### Error: psql command not found

Instalar cliente PostgreSQL en el agente:

```bash
apt-get install postgresql-client
```

### Error: password authentication failed

- Verificar credenciales en _admin/postgres-admin-credentials
- Verificar que el usuario tiene permisos para crear usuarios y BD
- Verificar que PostgreSQL permite conexiones desde el agente
