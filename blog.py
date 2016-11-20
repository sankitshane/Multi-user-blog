#Python lib imports
import os
import re
import random
import hashlib
import hmac
from string import letters
import time

#appengine and template imports
import webapp2
import jinja2

#database imports
from google.appengine.ext import db

#jinja Environment setup
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#random secret password
secret = 'shane'

#General functions
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Parent Class for the Blog
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#Parent Class for User
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Post Table
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    creator = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now = True)


    def render(self,ex_user,err="",post_id="",likes=""):
        self._render_text = self.content.replace('\n', '<br>')
        self.hits = 0
        for i in likes:
            if i.l_post == int(post_id):
                self.hits = self.hits + i.l_like
        return render_str("post.html", p = self,user = ex_user,error = err,post_id = post_id,likes = self.hits)

#Comments Table
class Comments(db.Model):
    c_title = db.StringProperty(required = True)
    c_content = db.StringProperty(required = True)
    c_post = db.StringProperty(required = True)
    c_created = db.DateTimeProperty(auto_now_add = True)
    c_creator = db.StringProperty()

    def render(self,post):
        if str(post.key().id()) == str(self.c_post):
            return render_str("Comm.html", c = self)
        else:
            return render_str("Comm.html")

class t_likes(db.Model):
    l_user = db.StringProperty(required = True)
    l_post = db.IntegerProperty(required = True)
    l_like = db.IntegerProperty( default = 0)

# Url /comment handler
class Comment(BlogHandler):
    def get(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if self.user:
                self.render("comments.html")
            else:
                self.redirect("/login")
        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)

    def post(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if not self.user:
                self.redirect('/blog')

                title = self.request.get('title')
                content = self.request.get('content')

                if title and content:
                    c = Comments(parent = blog_key(),c_title = title, c_content = content, c_creator =self.user.name, c_post = post_id)
                    c.put()
                    self.redirect('/blog')
                    time.sleep(0.1)
                else:
                    error = "title and content, please!"
                    self.render("comments.html",title=title, content=content, error=error)

        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)


# Url Likes handler
class likes(BlogHandler):
    def get(self,post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post:
                if self.user.name != post.creator:
                    row = db.GqlQuery("SELECT * FROM t_likes WHERE l_user = :1 AND l_post = :2",self.user.name,int(post_id)).get()
                    if row:
                        if row.l_like == -1:
                            row.l_like = 0
                            row.put()
                            self.redirect('/blog')
                            time.sleep(0.1)
                        elif row.l_like == 0:
                            row.l_like = 1
                            row.put()
                            self.redirect('/blog')
                            time.sleep(0.1)
                        else:
                            error = "You are already liked this post"
                            self.redirect('/blog?error='+error)
                    else:
                        new_row = t_likes(l_user = self.user.name, l_post = int(post_id), l_like=1).put()
                        self.redirect('/blog')
                        time.sleep(0.1)
                else:
                    error = "You are only allowed to like other's blog posts"
                    self.redirect('/blog?error='+error)
            else:
                error = "Post doesn't exist"
                self.redirect('/blog?error='+error)
        else:
            msg = "Please Log in to Like blog posts"
            self.render('login-form.html', error = msg)

#Url dislike Handler
class dislike(BlogHandler):
    def get(self,post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post:
                if self.user.name != post.creator:
                    row = db.GqlQuery("SELECT * FROM t_likes WHERE l_user = :1 AND l_post = :2",self.user.name,int(post_id)).get()
                    if row:
                        if row.l_like == 1:
                            row.l_like = 0
                            row.put()
                            self.redirect('/blog')
                            time.sleep(0.1)
                        elif row.l_like == 0:
                            row.l_like = -1
                            row.put()
                            self.redirect('/blog')
                            time.sleep(0.1)
                        else:
                            error = "You are already disliked this post"
                            self.redirect('/blog?error='+error)
                    else:
                        new_row = t_likes(l_user = self.user.name , l_post = int(post_id) , l_like = -1).put()
                        self.redirect('/blog')
                        time.sleep(0.1)
                else:
                    error = "You are only allowed to dislike other's blog posts"
                    self.redirect('/blog?error='+error)
            else:
                error = "Post doesn't exist"
                self.redirect('/blog?error='+error)
        else:
            msg = "Please Log in to disLike blog posts"
            self.render('login-form.html', error = msg)

#Url Edit Handler
class edit(BlogHandler):
    def get(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if self.user.name == post.creator:
                self.render('newpost.html',subject = post.subject , content = post.content, post= post)
            else:
                error = "You are only allowed to edit your own blog posts"
                self.redirect('/blog?error='+error)
        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)

    def post(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject, content=content, error=error)
        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)

#Url Delete Handler
class delete(BlogHandler):
    def get(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if self.user.name == post.creator:
                dele = "del"
                self.render("permalink.html", post = post,dele = dele)
            else:
                error = "You are only allowed to delete your own blog posts"
                self.redirect('/blog?error='+error)
        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)

    def post(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            post.delete()
            self.redirect('/blog')
            time.sleep(0.1)
        else:
            error = "Post doesn't exist"
            self.redirect('/blog?error='+error)
            
#Url Blog main page Handler
class BlogFront(BlogHandler):
    def get(self):
        error = self.request.get('error')
        posts = greetings = Post.all().order('-created')
        comments = Comments.all().order('-c_created')
        like = db.GqlQuery("SELECT l_post,l_like FROM t_likes")
        self.render('front.html', posts = posts,comments = comments,user = self.user,error = error,likes = like)

#Url specific Blog feed handler
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

#Url new Post handler
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, creator =self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

#Security part
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#Url Signup Handler
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

#Url User registeration handler
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

#Url Login Handler
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

#Url Logout Handler
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


# Main Page Url
class MainPage(BlogHandler):
  def get(self):
      self.render("welcome.html")

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/edit/([0-9]+)',edit),
                               ('/delete/([0-9]+)',delete),
                               ('/like/([0-9]+)',likes),
                               ('/dislike/([0-9]+)',dislike),
                               ('/comment/([0-9]+)',Comment),
                               ],
                              debug=True)
