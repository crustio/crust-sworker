pipeline {
    agent any
    stages {
        stage('Build') {
            script {
                currentBuild.displayName = "The name."
                currentBuild.description = "The best description."
            }
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
