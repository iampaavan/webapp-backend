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
						dockerImage = docker.build("${registry}:${GIT_COMMIT}")
					}
				}
			}
			stage('Deploy Docker Image to DockerHub')
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

