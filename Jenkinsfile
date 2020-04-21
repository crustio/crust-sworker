pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    currentBuild.displayName = "The name."
                    currentBuild.description = "The best description."
                }
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
