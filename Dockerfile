# Install dependencies only when needed
FROM whatwewant/builder-node:v20-1 AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apt update -y && apt install -y libpq-dev
RUN npm install -g pnpm
WORKDIR /app

ARG name

# copy packages and one project
COPY package.json .
COPY pnpm-lock.yaml .
COPY pnpm-workspace.yaml .
COPY ./packages ./packages
COPY ./projects/$name/package.json ./projects/$name/package.json

RUN ls -al && pnpm i

# Rebuild the source code only when needed
FROM whatwewant/builder-node:v20-1 AS builder

WORKDIR /app

ARG name

# copy common node_modules and one project node_modules
COPY package.json pnpm-workspace.yaml ./
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages ./packages
COPY ./projects/$name ./projects/$name
COPY --from=deps /app/projects/$name/node_modules ./projects/$name/node_modules

# Uncomment the following line in case you want to disable telemetry during the build.
ENV NEXT_TELEMETRY_DISABLED 1
RUN npm install -g pnpm
RUN pnpm --filter=$name run build

FROM whatwewant/node:v20-2 AS runner

WORKDIR /app

ARG name

# # create user and use it
# RUN addgroup --system --gid 1001 nodejs
# RUN adduser --system --uid 1001 nextjs

RUN sed -i 's/https/http/' /etc/apk/repositories
RUN apk add curl && apk add ca-certificates && update-ca-certificates

# copy running files
COPY --from=builder /app/projects/$name/public ./projects/$name/public
COPY --from=builder /app/projects/$name/next.config.js ./projects/$name/next.config.js
COPY --from=builder --chown=nextjs:nodejs /app/projects/$name/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/projects/$name/.next/static ./projects/$name/.next/static
# copy package.json to version file
COPY --from=builder /app/projects/$name/package.json ./package.json

COPY ./config/config.json /app/data/config.json

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1
ENV PORT=3000

EXPOSE 3000

ENV serverPath=./projects/$name/server.js

ENTRYPOINT ["sh","-c","node ${serverPath}"]
