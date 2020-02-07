pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			registryCredential = 'dockerhub'
			dockerImage = ''
			CC = """${sh(
                returnStdout: true,
                script: 'echo "clang"'
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
			    checkout scm
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
