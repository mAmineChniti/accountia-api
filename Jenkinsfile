pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'mAmineChniti/accountia-api'
        IMAGE_TAG = '1.0'
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials'
        NODE_OPTIONS = "--max-old-space-size=4096"
        CI = "true"
    }

    stages {
        stage('Install Dependencies') {
            steps {
                echo 'Installation des dépendances...'
                sh 'npm i --legacy-peer-deps'
            }
        }

        stage('Lint Check') {
            steps {
                echo 'Vérification ESLint...'
                sh 'npm run lint:check'
            }
        }

        stage('Format Check') {
            steps {
                echo 'Vérification du formatage Prettier...'
                sh 'npm run format:check'
            }
        }

        stage('Unit Tests') {
            steps {
                echo 'Exécution des tests unitaires...'
                sh 'npm run test:cov -- --runInBand'
            }
        }

        
        stage('SonarQube Analysis') {
            steps {
                script {
                    // Install sonar-scanner 6.1.0 (Java 17 compatible, no embedded JRE)
                    sh '''
                        if ! command -v sonar-scanner &> /dev/null; then
                            echo "Installing sonar-scanner 6.1.0..."
                            wget --timeout=30 --tries=3 -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-6.1.0.4477-linux.zip || {
                                echo "Failed to download sonar-scanner. Attempting alternative download..."
                                curl -L --connect-timeout 30 --max-time 300 -o sonar-scanner-cli-6.1.0.4477-linux.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-6.1.0.4477-linux.zip
                            }
                            unzip -qo sonar-scanner-cli-6.1.0.4477-linux.zip || { echo "Failed to extract sonar-scanner"; exit 1; }
                            chmod +x sonar-scanner-6.1.0.4477-linux/bin/sonar-scanner
                            echo "sonar-scanner installed successfully"
                        fi
                    '''
                    withSonarQubeEnv('SonarQube') {
                        sh '''
                            export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
                            export PATH=/usr/lib/jvm/java-17-openjdk/bin:$PATH
                            export PATH=$PWD/sonar-scanner-6.1.0.4477-linux/bin:$PATH
                            java -version
                            sonar-scanner -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300
                        '''
                    }
                }
            }
        }

        stage('Build Project') {
            steps {
                echo 'Compilation du projet...'
                sh 'npm run build'
            }
        }

        stage('Docker Build & Push') {
            steps {
                script {
                    sh 'docker build -t "$DOCKER_IMAGE:$IMAGE_TAG" -t "$DOCKER_IMAGE:latest" .'
                    withCredentials([usernamePassword(credentialsId: DOCKERHUB_CREDENTIALS_ID, usernameVariable: 'DOCKERHUB_USERNAME', passwordVariable: 'DOCKERHUB_PASSWORD')]) {
                        sh '''
                            echo "$DOCKERHUB_PASSWORD" | docker login -u "$DOCKERHUB_USERNAME" --password-stdin
                            docker push "$DOCKER_IMAGE:$IMAGE_TAG"
                            docker push "$DOCKER_IMAGE:latest"
                        '''
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline CI/CD Accountia API terminé avec succès !'
        }
        failure {
            echo 'Le pipeline a échoué. Vérifie les logs ci-dessus.'
        }

        cleanup {
            archiveArtifacts artifacts: 'coverage/**,.scannerwork/report-task.txt', allowEmptyArchive: true
            sh 'rm -rf sonar-scanner-* sonar-scanner-cli-*.zip .scannerwork/ || true'
            sh 'docker logout || true'
        }
    }
}
