pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			registryCredential = 'dockerhub'
			dockerImage = ''
	  }
	  agent any

	  stages
	  {
 			stage('Git Credentials')
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
