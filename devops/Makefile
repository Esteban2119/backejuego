build-image:
	@ docker build -f Dockerfile -t cocina:1 .

deploy:
	@ docker stack deploy --with-registry-auth -c stacksubdominio.yml esteb

rm:
	@ docker stack rm anita