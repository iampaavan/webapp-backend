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
			            sh ("pwd")
			            sh ("ls")
			            latestversion = getChartVersion()
			            newVersion = generateNewVersion("major")
			            echo latestversion
			            echo newVersion
			            sh ("yq w -i ./backend/Chart.yaml 'version' ${newVersion}")
			            sh ("yq r ./backend/Chart.yaml version")
			            sh ("yq r ./backend/values.yaml 'image.name'")
			            sh ("yq w -i ./backend/values.yaml" 'image.name' '${registry}:${GIT_COMMIT}')
			            sh ("yq r ./backend/values.yaml 'image.name'")
			        }
			    }
			}
	}
}
def getChartVersion(){
    def version = sh (returnStdout: true, script: 'yq r ./backend/Chart.yaml version')
    return version
}

def generateNewVersion(release){
    def (major, minor, patch) = getChartVersion().tokenize(".").collect{element -> return element.toInteger()}
    println(major.getClass())
    def newVersion
    if (release == 'major'){
        newVersion = "${major + 1}.0.0"
    }
    else if (release == 'minor'){
        newVersion = "${major}.${minor + 1}.0"
    }
    else if (release == 'patch'){
        newVersion = "${major}.${minor}.${patch + 1}"
    }
    return newVersion
}
