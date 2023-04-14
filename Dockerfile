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

FROM python:3.9
#FROM python:3.9-slim
LABEL org.opencontainers.image.source="https://github.com/UMinho-Netedge/netedge-mepm-uminho/"

RUN ["apt-get", "update"]

COPY ./ /home/netedge
ENV PATH="$PATH:/home/netedge/.local/bin"
RUN ["pip","install","-r","/home/netedge/requirements.txt"]

RUN ["apt-get", "-y", "install", "libcurl4-openssl-dev"]
RUN ["apt-get", "-y", "install", "libssl-dev"]
RUN ["pip", "install", "python-magic"]
RUN ["apt-get", "install", "-y", "git"]
RUN ["pip", "install", "git+https://osm.etsi.org/gerrit/osm/IM", "--upgrade"]
RUN ["pip", "install", "git+https://osm.etsi.org/gerrit/osm/osmclient"]
RUN ["pip", "install", "-r", "/home/netedge/osmclient/requirements.txt"]

ENV OSM_CLIENT_VERSION=v13.0

ENTRYPOINT ["python3"]
CMD ["/home/netedge/main.py","--mongodb_addr","127.0.0.1","--mongodb_database","mepm"]
