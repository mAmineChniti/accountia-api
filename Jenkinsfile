pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'mAmineChniti/accountia-api'
        IMAGE_TAG = '1.0'
        DOCKERHUB_CREDENTIALS_ID = 'dockerhub-credentials'
        NODE_OPTIONS = "--max-old-space-size=4096"
        CI = "true"
        SONAR_HOST_URL = 'http://localhost:9000'
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
                withCredentials([string(credentialsId: 'sonar', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        set -e
                        if [ -z "${SONAR_HOST_URL:-}" ]; then
                          echo "WARN: SONAR_HOST_URL not configured. Skipping SonarQube analysis."
                          exit 0
                        fi

                        if command -v sonar-scanner >/dev/null 2>&1; then
                          SCANNER_BIN=sonar-scanner
                        else
                          echo "Installing sonar-scanner CLI..."
                          wget --timeout=30 --tries=3 \
                            https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
                          unzip -qo sonar-scanner-cli-5.0.1.3006-linux.zip
                          chmod +x sonar-scanner-5.0.1.3006-linux/bin/sonar-scanner
                          SCANNER_BIN="$PWD/sonar-scanner-5.0.1.3006-linux/bin/sonar-scanner"
                        fi

                        "$SCANNER_BIN" \
                          -Dsonar.host.url="$SONAR_HOST_URL" \
                          -Dsonar.token="$SONAR_TOKEN" \
                          -Dsonar.qualitygate.wait=true \
                          -Dsonar.qualitygate.timeout=300
                    '''
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
                    sh '''
                        # Check if Docker daemon is accessible for Jenkins user
                        if ! docker ps > /dev/null 2>&1; then
                            echo "Docker daemon is not accessible for Jenkins user. Skipping Docker build & push."
                            exit 0
                        fi
                        
                                                # Create isolated Docker config without credential helpers
                                                mkdir -p .docker-ci
                                                cat > .docker-ci/config.json << 'EOF'
{
    "auths": {},
    "credHelpers": {}
}
EOF
                    '''
                    try {
                        sh '''
                            # Build without authentication (public image)
                            DOCKER_BUILDKIT=0 DOCKER_CONFIG="$PWD/.docker-ci" docker build --pull -t "$DOCKER_IMAGE:$IMAGE_TAG" -t "$DOCKER_IMAGE:latest" .
                        '''
                        
                        withCredentials([usernamePassword(credentialsId: DOCKERHUB_CREDENTIALS_ID, usernameVariable: 'DOCKERHUB_USERNAME', passwordVariable: 'DOCKERHUB_PASSWORD')]) {
                            sh '''
                                # Now login with credentials and push
                                printf '%s' "$DOCKERHUB_PASSWORD" | DOCKER_CONFIG="$PWD/.docker-ci" docker login -u "$DOCKERHUB_USERNAME" --password-stdin
                                DOCKER_CONFIG="$PWD/.docker-ci" docker push "$DOCKER_IMAGE:$IMAGE_TAG"
                                DOCKER_CONFIG="$PWD/.docker-ci" docker push "$DOCKER_IMAGE:latest"
                            '''
                        }
                    } catch (Exception e) {
                        echo "WARNING: Docker build/push failed or Docker credentials are unavailable: ${e.message}. Skipping Docker stage."
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
            sh 'rm -rf .docker-ci || true'
        }
    }
}
