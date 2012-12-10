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
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


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
        self.write(self.render_str(template,**kw))

class User_validation():
    # TODO(CG): implement hashing, username checking, etc.
    pass


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
        # TODO(CG): implement username registration, error checking, login, hashing, etc.
        pass
        


app = webapp2.WSGIApplication([
    ('/', BaseRedirect),
    ('/blog', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', Permalink),
    ('/blog/signup', Signup)
   ], debug=True)
