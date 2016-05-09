from flask import Flask
import flask
import os
import base64
import markdown
from markupsafe import Markup
import json
app = Flask(__name__)

app.config.from_pyfile('settings.py')

blogs = []
with open('data/data.json', 'r') as f:
    placeholder = (json.load(f))
    for item in placeholder:
        blogs.append({'title':item['title'], 'content':item['content']})


@app.route('/')
def index():
     CurrentPage = 0
     Length = len(blogs)
     tempBlogs = []
     if len(blogs) > 4:
         for i in range(0,5):
             tempBlogs.append(blogs[i])
     else:
         tempBlogs = blogs
     if 'csrf_token' not in flask.session:
        flask.session['csrf_token'] = base64.b64encode(os.urandom(32)).decode('ascii')
     auth_user = flask.session.get('auth_user', None)
     resp = flask.make_response(flask.render_template('index.html', auth_user=auth_user,
                                                     csrf_token=flask.session['csrf_token'],Length = Length, CurrentPage = CurrentPage,
                                                      blogs = tempBlogs))
     return resp

@app.route('/<int:pageNum>')
def page_Handler(pageNum):
    if 'csrf_token' not in flask.session:
        flask.session['csrf_token'] = base64.b64encode(os.urandom(32)).decode('ascii')
    auth_user = flask.session.get('auth_user', None)
    tempBlogs = []
    max = 0
    if (pageNum + 5) < len(blogs):
        max = pageNum + 5
    else:
        max = len(blogs)
    for i in range(pageNum,max):
        tempBlogs.append(blogs[i])
    Length = len(blogs)
    resp = flask.make_response(flask.render_template('index.html', auth_user=auth_user,
                                                     csrf_token=flask.session['csrf_token'], check=1, blogs = tempBlogs,
                                CurrentPage = pageNum, Length = Length))
    return resp

@app.route('/login', methods=['POST'])
def handle_login():
    # POST request to /login - check user
    user = flask.request.form['user']
    password = flask.request.form['password']
    if user == 'admin' and password == app.config['ADMIN_PASSWORD']:
        # User is good! Save in the session
        flask.session['auth_user'] = user
        # And redirect to '/', since this is a successful POST
        return flask.redirect('/', 303)
    else:
        # For an error in POST, we'll just re-show the form with an error message
        return flask.render_template('index.html', state='bad', CurrentPage = 0, Length = len(blogs))

@app.route('/logout')
def handle_logout():
    # user wants to say goodbye, just forget about them
    del flask.session['auth_user']
    return flask.redirect('/')

@app.errorhandler(404)
def not_found(err):
    return (flask.render_template('404.html', path=flask.request.path), 404)

@app.route('/addBlogButton')
def add_Blog():
    return flask.render_template('addBlog.html', auth_user=flask.session.get('auth_user', None),csrf_token=flask.session['csrf_token'])

@app.route('/addBlog', methods=['POST'])
def add_Blog_Handle():
    if 'auth_user' not in flask.session:
        app.logger.warn('unauthorized user tried to add blog')
        flask.abort(401)
    if flask.request.form['_csrf_token'] != flask.session['csrf_token']:
        app.logger.debug('invalid CSRF token in blog form')
        flask.abort(400)

    title = flask.request.form['title']
    if title == "":
        title =  "None"
    content = flask.request.form['content']
    if content == "":
        return flask.render_template('addBlog.html',csrf_token=flask.session['csrf_token'], check = 0)
    blogs.append({'title':title,'content':content})
    with open('data/data.json', 'w') as f:
        json.dump(blogs, f)
    return flask.redirect(flask.url_for('posts', pid=len(blogs) - 1), code=303)

@app.route('/posts/<int:pid>')
def posts(pid):
    tempPost = blogs[pid]
    content = Markup(markdown.markdown(tempPost['content'], output_format='html5'))
    return flask.render_template('posts.html', tempPost = tempPost, content = content ,pid = pid,
                                 csrf_token=flask.session['csrf_token'])

@app.route('/removeBlog',methods = ['POST'])
def remove_Blog_Handle():
    if 'auth_user' not in flask.session:
        app.logger.warn('unauthorized user tried to add animal')
        flask.abort(401)
    if flask.request.form['_csrf_token'] != flask.session['csrf_token']:
        app.logger.debug('invalid CSRF token in blog form')
        flask.abort(400)

    id = int(flask.request.form['id'])
    blogs.remove(blogs[id])
    with open('data/data.json', 'w') as f:
        json.dump(blogs, f)
    return flask.redirect(flask.url_for('index'))

if __name__ == '__main__':
    app.run(debug = True)
