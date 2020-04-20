pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
                ls
                cd Miner
                ls
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