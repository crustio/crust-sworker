void setBuildStatus(context, message, state) {
  step([
      $class: "GitHubCommitStatusSetter",
      contextSource: [$class: "ManuallyEnteredCommitContextSource", context: context],
      errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
      reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.com/crustio/crust-tee"],
      statusResultSource: [ $class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]] ]
  ]);
}

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
    post {
    success {
        setBuildStatus(context, "Build succeeded", "SUCCESS");
    }
    failure {
        setBuildStatus(context, "Build failed", "FAILURE");
    }
  }
}
