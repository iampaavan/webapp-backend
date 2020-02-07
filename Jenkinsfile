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
					dockerImage = docker.build("foo", "--build-arg vcs-ref=${GIT_COMMIT} .")
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
