pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                sh """
                make clean
                make -j4
                """
                echo 'Build successfully'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing...'
                sh """
                make clean
                make -j4 test
                """
                echo 'Test successfully'
            }
        }
    }
}
