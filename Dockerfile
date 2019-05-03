FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:changeme' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

# install Faucet
RUN apt-get install curl gnupg apt-transport-https lsb-release -y \
    && echo "deb https://packagecloud.io/faucetsdn/faucet/$(lsb_release -si | awk '{print tolower($0)}')/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/faucet.list \
    && curl -L https://packagecloud.io/faucetsdn/faucet/gpgkey | apt-key add - \
    && apt-get update \
    && apt-get install faucet -y

EXPOSE 22 
ExPOSE 6653

CMD /etc/init.d/ssh start && faucet
# sudo docker build -t mohmd/faucet-ssh .
