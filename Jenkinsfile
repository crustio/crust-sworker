pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                cd Miner
                make
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
    }
}