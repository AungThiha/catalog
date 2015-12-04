# catalog
Full-Stack Web Nanodegree ( Project 3 )

The project is a catalog app with dummy data.<br>
The project consists of:<br>
* Setting up database
* CRUD operation
* Showing Flash Messages
* Implementing API end points
* Styling and improving user experience
* Authentication and authorization

### Requirements
* Python 2.7 or above
* SQLite 3
* Flask
* sqlalchemy
* oauth2client
* Git
* Terminal or command prompt

### How to download
Open up your terminal or command prompt and enter the following command to download
* $ git clone git@github.com:AungThiha/catalog.git

### How To create database and add dummy data
Make sure the current directly is where all the codes downloaded under.<br>
In your terminal or command prompt, run the following command<br>
* $ python catalog_data.py

You will see a sqlite database file named "catalog.db" is created.

### How To setup gplus client id and other necessary stuffs
* Follow this [tutorial](http://support.heateor.com/how-to-get-google-plus-client-id/) first
* In google developer console, open left navigation drawer
* API Manager -> Credential -> Click your created credential -> Click download json
* make sure redirect_uris and javascript_origins in downloaded json are not empty. if it's empty, go back and figure out what's wrong
* replace content of client_secrets.json with the content of downloaded json

### How To setup fb app id and other neccessary stuffs
* Follow this [tutorial](http://commandotubetools.com/stctutorials/how-to-get-and-add-facebook-client-id-and-app-secret/) (two final steps are not necessary)
* replace some placeholder text from fb_client_secrets.json with appropriate values obtained from created fb app

### How To run the application
Open up your terminal or command prompt and run the command below:<br>
* $ python application.py

### API end points
* get data in json

> {base_url}/catalog.json

* get data in xml

> {base_url}/catalog.xml

