pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                sh """
                ls
                cd Miner
                ls
                make
                """
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
    }
}