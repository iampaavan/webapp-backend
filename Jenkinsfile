pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			registryCredential = 'dockerhub'
			dockerImage = ''
			CC = """${sh(
                returnStdout: true,
                script: 'git rev-parse HEAD'
            )}"""
	  }
	  agent any

	  stages
	  {
 			stage('Git Checkout')
 			{
 		   steps
 		   		{
 						checkout scm
 					}
 		}
		stage('Build Docker Image')
		{
			steps
			{
				script
				{
				        sh 'printenv'
						dockerImage = docker.build registry + ":$BUILD_NUMBER"
				}
			}
		}
		stage('Deploy Docker Image')
		{
			steps
			{
				 script
				 {
					docker.withRegistry( '', registryCredential )
						{
							dockerImage.push()
						}
				 }
			}
		}
	}
}
