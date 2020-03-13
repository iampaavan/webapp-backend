pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			registryCredential = 'dockerhub'
			githubCredential = 'github'
			dockerImage = ''
			GIT_COMMIT = """${sh(
                returnStdout: true,
                script: 'git rev-parse HEAD'
            ).trim()}"""
	  }
	  agent any
	  stages
	  {
//  			stage('Git Checkout')
//  			{
//  		   steps
//  		   		{
//  						checkout scm
//  					}
//  		}
// 			stage('Build Docker Image')
// 			{
// 				steps
// 				{
// 					script
// 					{
// 						dockerImage = docker.build("${registry}:${GIT_COMMIT}")
// 					}
// 				}
// 			}
// 			stage('Deploy Docker Image to DockerHub')
// 			{
// 				steps
// 				{
// 					 script
// 					 {
// 						docker.withRegistry( '', registryCredential )
// 							{
// 								dockerImage.push()
// 							}
// 					 }
// 				}
// 			}
			stage('clone helm chart repo')
			{
			    steps
			    {
			        script
			        {
			            git (branch: 'jenkins-test',
			                 credentialsId: githubCredential,
			                 url: 'https://github.com/hemalgadhiya/helm-charts.git')
			            sh "pwd"
			            sh "ls"
			            latestversion = getChartVersion()
			            echo latestversion
			        }
			    }
			}
	}
}
def getChartVersion(){
    def version = sh (returnStdout: true, script: 'yq r ./backend/Chart.yaml version')
    println(version.getClass())
    def split = version.split(".")
    println(split)
    return split
}
