pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                sh """
                cd src
                make clean
                make
                """
                echo 'Build successfully'
            }
        }
    }
}
