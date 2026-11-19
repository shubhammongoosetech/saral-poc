.PHONY: all build clean test dev docker-poc docker-full docker-down docker-status verify prisma-generate prisma-migrate

all: build

build:
	npm run build

clean:
	npm run clean

prisma-generate:
	npm run prisma:generate

prisma-migrate:
	npm run prisma:migrate

test:
	npm run test

verify:
	npm run verify:architecture

dev:
	npm run dev

docker-poc:
	npm run docker:poc

docker-full:
	npm run docker:full

docker-down:
	npm run docker:down

docker-status:
	npm run docker:status

