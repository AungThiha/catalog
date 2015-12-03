from flask import Flask

app = Flask(__name__)

@app.route('/')
def show_home():
    return 'this is going to be homepage'


@app.route('/catalog/<int:catalog_id>/')
def show_catalog():
    return 'show catalog'


@app.route('/catalog/<int:catalog_id>.json')
def show_catalog_json():
    return 'show catalog'


@app.route('/catalog/<int:catalog_id>/new')
def add_item():
    return 'add item'


@app.route('/catalog/<int:catalog_id>/<int:item_id>/')
def show_item():
    return 'show item'


@app.route('/catalog/<int:catalog_id>/<int:item_id>/edit')
def edit_item():
    return 'edit item'


@app.route('/catalog/<int:catalog_id>/<int:item_id>/delete')
def edit_item():
    return 'delete item'


if __name__ == '__main__':
    app.run()
