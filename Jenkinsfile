pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                sh """
                make clean
                make
                """
                echo 'Build successfully'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing...'
                sh """
                make clean
                make test
                """
                echo 'Test successfully'
            }
        }
    }
}
