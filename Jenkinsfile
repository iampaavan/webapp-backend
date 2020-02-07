pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			registryCredential = 'dockerhub'
			dockerImage = ''
			GIT_COMMIT = """${sh(
                returnStdout: true,
                script: 'git rev-parse HEAD'
            ).trim()}"""
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
					dockerImage = docker.build("${GIT_COMMIT}")
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
