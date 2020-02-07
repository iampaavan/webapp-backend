pipeline
	{
	  environment
	  {
			registry = "hemalgadhiya/csye-7374-advanced-cloud-webapp-backend"
			registryCredential = 'dockerhub'
			dockerImage = ''
	  }
	  agent any

	  stages
	  {
// 		stage('Git Credentials')
// 		{
// 		   steps
// 		   {
// 				git([url: 'https://github.com/CSYE-7374-Advanced-Cloud-Computing/webapp-backend.git', branch: 'assignment4', credentialsId: 'github'])
// 			}
// 		}
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
