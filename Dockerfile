# Copyright 2022 Centro ALGORITMI - University of Minho
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.


FROM alpine:3.17.1

LABEL org.opencontainers.image.source="https://github.com/UMinho-Netedge/netedge-mepm-uminho/"

RUN adduser -D -h /home/netedge netedge
#RUN useradd -m -d /home/netedge netedge

RUN apk update
RUN apk add --no-cache python3 py3-pip
#RUN ["apt-get", "update"]

COPY ./ /home/netedge
USER netedge
ENV PATH="$PATH:/home/netedge/.local/bin"
#RUN ["/usr/local/bin/python", "-m", "pip", "install", "--upgrade", "pip"]
RUN ["pip","install","-r","/home/netedge/requirements.txt"]

ENTRYPOINT ["python3"]
CMD ["/home/netedge/main.py","--mongodb_addr","127.0.0.1","--mongodb_database","mepm"]
