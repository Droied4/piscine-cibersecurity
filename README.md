# Piscine-Cibersecurity
- [Day 1](#Day-1)
- [Day 2](#Day-2)
- [Day 3](#Day-3)

## Day 1

### Spider

Usage
```
./spider [-r recursive -l recursive_level -p path] {url} 
````
[Spider](./ex01/01_arachnida) design and implement a Ruby mini web crawler that automatically traversed internal website pages, collecting images and links.
#### What is a web crawler?
A web crawler, spider, or search engine bot is a software program that accesses, downloads, and/or indexes content from all over the Internet. Web crawler operators may seek to learn what (almost) every webpage on the web is about, so that the information can be retrieved when it's needed. Search engine operators may use these bots to find relevant pages to display in search results. The bots are called "web crawlers" because crawling is the technical term for automatically accessing a website and obtaining data via a software program.
#### why it is called spider?
The Internet, or at least the part that most users access, is also known as the World Wide Web — in fact that's where the "www" part of most website URLs comes from. It was only natural to call search engine bots "spiders," because they crawl all over the Web, just as real spiders crawl on spiderwebs.

### Scorpion

Usage
```
./scorpion [FILE 1] [FILE 2] [ ... ]
````
[Scorpion](./ex01/02_scorpion) is designed to extract and analyze EXIF metadata from image files. By simply passing a file as an argument, Scorpion inspects embedded metadata such as camera settings, timestamps, geolocation data, and other technical details stored within the file. Using FastImage and exif libraries.
#### What is EXIF Data ? 
Exchangeable Image File Format (EXIF) is a standard that defines specific information related to an image or other media captured by a digital camera. It is capable of storing such important data as camera exposure, date/time the image was captured, and even GPS location.

## Day 2

Usage
```
./ft_otp [-g create encrypted file -k create password] File
```
[FT_OTP](./ex02/ft_otp) is an implementation of the HOTP alghorithm.
Message Authentication Code, or MAC, is a crypto checksum for data transferred through insecure channels. With MAC applied the receiving party can verify the authenticity of the message simply by establishing that the sender has the secret key. In case the sender does not have the correct seed, the MAC value would be wrong and the recipient would know the message was not sent from the legitimate sender.

## Day 3

Usage
```shell
make
#On the docker container to know the url onion (only accesible via Tor browser)
docker exec -it nginx sh
cat /var/lib/tor/onion_service/hostname
ssh -p 4242 nginx@localhost
# password(pass)
```
[FT_OTP](./ex03/onion) We learnt about Tor and hidden services the objetive is create a web server using nginx in a docker container and serve a static website with onion url
