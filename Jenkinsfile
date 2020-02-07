pipeline
	{
	  environment
	  {
			registry = "iampaavan/csye-7374-advanced-cloud-webapp-backend"
			registryCredential = 'dockerhub'
			dockerImage = ''
	  }
	  agent any

	  stages
	  {
		stage('Git credentials')
		{
		   steps
		   {
				git([url: 'https://github.com/CSYE-7374-Advanced-Cloud-Computing/webapp-backend.git', branch: 'assignment4', credentialsId: 'github'])
			}
		}
		stage('Build Image')
		{
			steps
			{
				script
				{
					dir("/var/lib/jenkins/workspace/docker-test/recipe_management/")
					{
						dockerImage = docker.build registry + ":$BUILD_NUMBER"
					}
				}
			}
		}
		stage('Deploy Image')
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
