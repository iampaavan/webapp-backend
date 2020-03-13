pipeline
	{
	  environment
	  {
			registry = credentials("docker_registery")
			docker_username = credentials("user_name")
		    docker_password = credentials("password")
		    s3_bucket = credentials("bucketname")
		    access_key = credentials("aws_access_key")
		    secret_key = credentials("aws_secret_key")
		    rds_url = credentials("rds_url")
		    redis_password = credentials("redis_password")
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
			            newVersion = generateNewVersion("patch")
			            echo latestversion
			            echo newVersion
			            sh ("yq r ./backend/Chart.yaml version")
			            sh ("yq w -i ./backend/Chart.yaml 'version' ${newVersion}")
			            sh ("yq r ./backend/Chart.yaml version")
			            sh ("yq r ./backend/values.yaml 'image.name'")
			            sh ("yq w -i ./backend/values.yaml 'image.name' '${registry}:${GIT_COMMIT}'")
			            sh ("yq r ./backend/values.yaml 'image.name'")
			            sh ("yq w -i ./backend/values.yaml 'imageCredentials.username' ${docker_username}")
			            sh ("yq w -i ./backend/values.yaml 'imageCredentials.password' ${docker_password}")
			            sh ("yq w -i ./backend/values.yaml 'bucketname' ${s3_bucket}")
			            sh ("yq w -i ./backend/values.yaml 'awsAccessKey' ${access_key}")
			            sh ("yq w -i ./backend/values.yaml 'awsSecretKey' ${secret_key}")
			            sh ("yq w -i ./backend/values.yaml 'dbsecret.rdsurl' ${rds_url}")
			            sh ("yq w -i ./backend/values.yaml 'redis.password' ${redis_password}")
			            sh ('git config --global user.email "hemalgadhiya@gmail.com"')
			            sh ('git config --global user.name "Hemal Gadhiya"')
			            sh ("git add --all")
			            sh ('git commit -m "testing jenkins ci/cd"')
			            withCredentials([usernamePassword(credentialsId: 'github', passwordVariable: 'GIT_PASSWORD', usernameVariable: 'GIT_USERNAME')]) {
                        sh('git push https://${GIT_USERNAME}:${GIT_PASSWORD}@github.com/hemalgadhiya/helm-charts.git jenkins-test')
                    }
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