#/bin/bash

###########
# PURPOSE #
###########
# Run the docker image
#
# Prerequisites:
# - docker

#########
# USAGE #
#########
# To run docker interactively (mounts the current directory):
# $ path/to/build-docker.sh
#
# To run a specific command withing docker (e.g.):
# $ path/to/build-docker.sh make test

############
# SETTINGS #
############

IMAGE=avalon-evm4ccf-dev

###############
# PREPARATION #
###############
# determine directory containing this script

sysname=`uname`
if [[ $sysname =~ "Darwin" ]];then
    BASEDIR="$(cd "$(dirname "$0")"; pwd)"
else
    BASEDIR="$(dirname "$(readlink -f "$0")")"
fi


############################
# BUILD DOCKER #
############################

# build the docker image
sudo docker build -t $IMAGE .

# show details of each layer of the docker image
ID=$(docker images --filter=reference=$IMAGE --format "{{.ID}}")
echo $ID
docker history --format "table {{printf \"%.150s\" .CreatedBy}}\t{{.Size}}" --no-trunc $ID


##############
# RUN DOCKER #
##############
# --rm: automatically clean up the container when the container exits
# --workdir: Working directory inside the container
# -v: Bind mount a volume from the host

WORKDIR="/project/evm4ccf"
if [ $# -eq 0 ]; then
	# no arguments supplied
	echo "Running docker interactively..."
	DIR="$(pwd)"
	FLAGS="-v $DIR:$WORKDIR --workdir $WORKDIR"
else
	echo "Running in docker: $@"
	FLAGS="--workdir $WORKDIR"
fi


sudo docker run \
	--rm
	-it \
	$FLAGS \
	$IMAGE \
	"$@"

