#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import string
import random
import hashlib
import re

from google.appengine.ext import db
from collections import namedtuple


template_dir = os.path.join(os.path.dirname(__file__), 'templates')    # __file__ is *this* file
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


### MODELS ###

class BlogPosts(db.Model):
    """Create datastore with subject, content, and created date."""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)


### HELPER FUNCTIONS ###

user_re = re.compile("^[a-zA-Z0-9_-]{3,20}$")
pass_re = re.compile("^.{3,20}$")
email_re = re.compile("^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return user_re.match(username)

def valid_password(password):
    return pass_re.match(password)

def valid_email(email):
    return email_re.match(email)

def make_salt():
    """Generate a random 5-character string to use as a password salt"""
    salt = ''
    for i in xrange(5):
        salt += random.choice(string.ascii_letters)
    return salt

def make_pw_hash(name, pw, salt=None):
    """Use sha256 hash function to create or validate a username/password hash combination"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return (salt, h)

def valid_pw(name, pw, h):
    """Validate a username/password combination"""
    hash,salt = h.split(',')
    if make_pw_hash(name,pw,salt) == h:
        return True


### HELPER CLASSES ###

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        """Helper function for render()"""
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        """Helper function for render()"""
        jinja_template = jinja_env.get_template(template)
        return jinja_template.render(params)

    def render(self, template, **kw):
        """Helper function combining self.write and self.redner_str that is exposed to dependent classes"""
        kw['signedIn'] = self.request.cookies.get('user_id', None)
        self.write(self.render_str(template,**kw))


### PAGE HANDLERS ###

class BaseRedirect(webapp2.RequestHandler):
    """Redirect to blog homepage"""
    def get(self):
        self.redirect('/blog')


class MainPage(Handler):
    """Basic landing page"""
    def get(self):
        posts_from_db = db.GqlQuery("SELECT * FROM BlogPosts ORDER BY created DESC")
        self.render("main.html",posts=posts_from_db)


class NewPost(Handler):
    """Add a new post to the blog"""
    def get(self,**params):
        self.render("form.html",**params)
    
    def post(self):
        entry_data = {}
        entry_data['subject'] = self.request.get('subject')
        entry_data['content'] = self.request.get('content')
        

        if entry_data['subject'] and entry_data['content']:
            bp = BlogPosts(**entry_data)
            post_key = bp.put()    # Write the values to the model
        
            self.redirect('/blog/%d' % int(post_key.id()))
            
        else:
            entry_data['error'] = "You need both a valid subject and content."
            self.get(**entry_data)    # redirect to the same page and re-render with error messages


class Permalink(Handler):
    def get(self,entry_id):
        key = db.Key.from_path('BlogPosts', int(entry_id))    # Look for a post by entry_id
        bp = db.get(key)
        
        if not bp:
            self.redirect('/404')    # Kludge way to use the built-in 404 handler (for consistency)
            return
        
        self.render("main.html", posts=[bp], menu="home")


class Signup(Handler):
    def get(self):
        self.render("signup.html",error={})

    def post(self):
        error = {}
        username = self.request.get('username')
        password = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')

        user_from_db = db.GqlQuery("SELECT * FROM Users where username=:1", username).get()

        if not username or not valid_username(username): # username is required and must be valid
            error['username'] = 'Invalid username.'
        elif user_from_db and username == user_from_db.username: # user should not exist in the db
            error['username'] = 'User already exists.'
        elif not password or not valid_password(password): # password is required and must be valid
            error['password'] = 'Invalid password.'
        elif not password2 or password != password2: # make sure password matches
            error['verify'] = 'Passwords do not match.'
        elif email and not valid_email(email): # validate email if given
            error['email'] = 'Invalid email address.'

        if error:
            self.render("signup.html",error=error)
        else:
            salt,h = make_pw_hash(username,password)
            user = Users(username = username,
                         pw_hash = h,
                         salt = salt)
            user.put()
            user_id = user.key().id()
            self.response.headers.add_header('Set-Cookie', 'user_id=%d|%s' % (user_id,h))
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        error = {}
        username = self.request.get('username')
        password = self.request.get('password')

        user_from_db = db.GqlQuery("SELECT * FROM Users where username=:1", username).get()

        if (not username or not password or
            not valid_username(username) or
            not valid_password(password) or
            not user_from_db or
            username != user_from_db.username):
            error = 'Invalid login'

        if error:
            self.render("login.html",error=error)
        else:
            salt,h = make_pw_hash(username,password)
            user = Users(username = username,
                         pw_hash = h,
                         salt = salt)
            user.put()
            user_id = user.key().id()
            self.response.headers.add_header('Set-Cookie', 'user_id=%d|%s' % (user_id,h))
            self.redirect('/blog/welcome')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=')
        self.redirect('/blog/login')


class Welcome(Handler):
    def get(self):
        user_cookie = self.request.cookies.get('user_id', None)
        if not user_cookie:
            self.redirect('/blog/signup')
        cookie_user_id,cookie_h = tuple(user_cookie.split('|'))
        user = Users.get_by_id(int(cookie_user_id))
        if not cookie_h == user.pw_hash:
            self.redirect('/blog/signup')
        else:
            self.render("welcome.html",username=user.username)


app = webapp2.WSGIApplication([
    ('/', BaseRedirect),
    ('/blog', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', Permalink),
    ('/blog/signup', Signup),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/welcome', Welcome)
   ], debug=True)
