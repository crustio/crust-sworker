pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                sh """
                cd Miner
                make clean
                make
                """
                echo 'Build successfully'
            }
        }
    }
}
