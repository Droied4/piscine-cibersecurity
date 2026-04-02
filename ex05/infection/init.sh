#!/bin/sh

set -e

prepare_environment()
{
	path=$1	
	if [ ! -d $path ]; then 
		mkdir -p $path 
	fi

	if [ ! -f $path/stockholm ]; then
		mv /app/stockholm $path/stockholm
	fi

	echo "The program is now in the controled environment"
}

get_dependencies()
{
	apk add curl 
}

create_test()
{
	path=$1	
	echo "Creating files to test"
	echo "Este es un test sencillo de numeros 42 y texto bastante simple que comprueba el funcionamiento del programa siuuuu :D!!!!!!" > $path/texto.txt
	curl -L 'https://img.asmedia.epimg.net/resizer/v2/47CSAGX3JNGLBCXJUUMYXFPB7Y.jpg?auth=d974a8b9df6778f3f412dc2d85cba860aee0d9cdf353c1e8125be86de79de103&width=1472&height=1104&smart=true' > $path/walter.jpg
	curl -L 'https://www.42barcelona.com/' > $path/barcelona
}

init()
{
	prepare_environment "$HOME/infection"
	get_dependencies
	create_test "$HOME/infection"
}

if [ "$1" = "ruby" ]; then
	init "$@"
else
	exec "$@"
fi
