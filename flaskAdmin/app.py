import json
import os
import time
from io import StringIO

import jsonpickle
import jwt
from flask import Flask, redirect, url_for, flash, request, Request
from flask.json import dump
from flask_admin.babel import gettext, ngettext
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import FormOpts
from flask_admin.helpers import get_redirect_target, flash_errors
from flask_admin.model.helpers import get_mdict_item_or_list
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask import jsonify

from flask_admin import Admin, expose

import pika
from pika import BlockingConnection
from werkzeug import Response

app = Flask(__name__,static_url_path='',
            static_folder='./static')
app.debug = True

app.config['FLASK_ENV'] = os.getenv("FLASK_ENV")
# Scheme: "postgres+psycopg2://<USERNAME>:<PASSWORD>@<IP_ADDRESS>:<PORT>/<DATABASE_NAME>"
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@pg_db:5432/{os.getenv("POSTGRES_DB")}'
# app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://flask:flask@localhost:5432/flask'
app.config['SECRET_KEY'] = "anysecret"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
# connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))

# class middleware():
#     '''
#     Simple WSGI middleware
#     '''
#
#     def __init__(self, app):
#         self.app = app
#
#     def __call__(self, environ, start_response):
#         request = Request(environ)
#
#         if "admin" not in request.url:
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#
#         claims = request.headers.get("Authorization")
#         if claims == "":
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#
#         token = jwt.decode(claims, os.getenv("SECRET_KEY"), algorithms=["HS256"])
#         if token['login'] == "":
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#         if token['role_id'] == 0:
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#         elif token['role_id'] != 1:
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#         if token['id'] == "":
#             res = Response(u'Authorization failed', mimetype='text/plain', status=401)
#             return res(environ, start_response)
#
#         return self.app(environ, start_response)
#
#
# app.wsgi_app = middleware(app.wsgi_app)


class CategoryConnection:

    def __init__(self, connection):
        self.connection = connection

    def AddCategory(self, model):
        while True:
            try:
                channel = self.connection.channel()
                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                app.logger.info(jsonpickle.dumps(model.toDict()))
                channel.basic_publish(exchange='Shopper',
                                      routing_key='addCategory',
                                      body=jsonpickle.dumps(model.toDict()))
                return

            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))

    def ChangeCategory(self, model, form):
        while True:
            try:
                channel = self.connection.channel()
                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                channel.basic_publish(exchange='Shopper',
                                      routing_key='changeCategory',
                                      body=jsonpickle.dumps(ToDict(model.id, form.data["name"],
                                                                   None if form.data["parent"] is None else form.data[
                                                                       "parent"].id)))
                return

            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))

    def DeleteCategory(self, model):
        while True:
            try:
                channel = self.connection.channel()

                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                app.logger.info(jsonpickle.dumps(model.toDict()))
                channel.basic_publish(exchange='Shopper',
                                      routing_key='deleteCategory',
                                      body=jsonpickle.dumps(model.toDict()))
                return
            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))


class ProductConnection:

    def __init__(self, connection):
        self.connection = connection

    def AddProduct(self, model):
        while True:
            try:
                channel = self.connection.channel()
                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                channel.basic_publish(exchange='Shopper',
                                      routing_key='addProduct',
                                      body=jsonpickle.dumps(model.toDict()))
                return

            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))

    def ChangeProduct(self, model, form):
        while True:
            try:
                channel = self.connection.channel()
                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                channel.basic_publish(exchange='Shopper',
                                      routing_key='changeProduct',
                                      body=jsonpickle.dumps(
                                          ToProductDict(model.id, form.data["name"], form.data["price"],
                                                        form.data["image_url"],
                                                        None if "category_of_items" not in form.data else
                                                        form.data[
                                                            "category_of_items"].id)))
                return

            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))

    def DeleteProduct(self, model):
        while True:
            try:
                channel = self.connection.channel()

                channel.exchange_declare(exchange='Shopper',
                                         exchange_type='direct', auto_delete=True)
                app.logger.info(jsonpickle.dumps(model.toDict()))
                channel.basic_publish(exchange='Shopper',
                                      routing_key='deleteProduct',
                                      body=jsonpickle.dumps(model.toDict()))
                return
            except Exception:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters('rabbitmq'))


class Category(db.Model):
    __tablename__ = "category"

    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(20), unique=False, nullable=False)
    items_in_category = db.relationship('Items', uselist=False,
                                        cascade="delete")
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'), index=True)
    parent = db.relationship(lambda: Category, remote_side=id, backref='sub_category')

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.toDict(),
                          sort_keys=True, indent=4)

    def __repr__(self):
        return self.name

    def toDict(self):
        return {'id': self.id, 'name': self.name, 'parent': self.parent_id}


def ToDict(id, name, parent_id):
    return {'id': id, 'name': name, 'parent': parent_id}


def ToProductDict(id, name, price, image_url, item_category):
    return {'id': id, 'name': name, 'price': price, 'image_url': image_url,
            'item_category': item_category}


class CategoryView(ModelView):
    column_list = (
        'name', 'parent',
    )
    form_columns = (
        'name', 'parent',
    )

    @expose('/new/', methods=('GET', 'POST'))
    def create_view(self):
        """
            Create model view
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_create:
            return redirect(return_url)

        form = self.create_form()
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_create_rules, form=form)

        if self.validate_form(form):
            # in versions 1.1.0 and before, this returns a boolean
            # in later versions, this is the model itself
            model = self.create_model(form)

            if model:
                # RabbitMQ
                catcon = CategoryConnection(connection)
                catcon.AddCategory(model)

                # model.id model.name changed
                flash(gettext('Record was successfully created.'), 'success')
                if '_add_another' in request.form:
                    return redirect(request.url)
                elif '_continue_editing' in request.form:
                    # if we have a valid model, try to go to the edit view
                    if model is not True:
                        url = self.get_url('.edit_view', id=self.get_pk_value(model), url=return_url)
                    else:
                        url = return_url
                    return redirect(url)
                else:
                    # save button

                    return redirect(self.get_save_return_url(model, is_created=True))

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_create_rules)

        if self.create_modal and request.args.get('modal'):
            template = self.create_modal_template
        else:
            template = self.create_template

        return self.render(template,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @expose('/edit/', methods=('GET', 'POST'))
    def edit_view(self):
        """
            Edit model view
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_edit:
            return redirect(return_url)

        id = get_mdict_item_or_list(request.args, 'id')
        if id is None:
            return redirect(return_url)

        model = self.get_one(id)

        if model is None:
            flash(gettext('Record does not exist.'), 'error')
            return redirect(return_url)

        form = self.edit_form(obj=model)
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_edit_rules, form=form)

        if self.validate_form(form):
            if self.update_model(form, model):

                # RabbitMQ
                catcon = CategoryConnection(connection)
                catcon.ChangeCategory(model, form)

                flash(gettext('Record was successfully saved.'), 'success')
                if '_add_another' in request.form:
                    return redirect(self.get_url('.create_view', url=return_url))
                elif '_continue_editing' in request.form:
                    return redirect(self.get_url('.edit_view', id=self.get_pk_value(model)))
                else:
                    # save button
                    return redirect(self.get_save_return_url(model, is_created=False))

        if request.method == 'GET' or form.errors:
            self.on_form_prefill(form, id)

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_edit_rules)

        if self.edit_modal and request.args.get('modal'):
            template = self.edit_modal_template
        else:
            template = self.edit_template

        return self.render(template,
                           model=model,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @expose('/delete/', methods=('POST',))
    def delete_view(self):
        """
            Delete model view. Only POST method is allowed.
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_delete:
            return redirect(return_url)

        form = self.delete_form()

        if self.validate_form(form):
            # id is InputRequired()
            id = form.id.data

            model = self.get_one(id)

            if model is None:
                flash(gettext('Record does not exist.'), 'error')
                return redirect(return_url)

            # RabbitMQ
            catcon = CategoryConnection(connection)
            catcon.DeleteCategory(model)

            # message is flashed from within delete_model if it fails
            if self.delete_model(model):
                count = 1
                flash(
                    ngettext('Record was successfully deleted.',
                             '%(count)s records were successfully deleted.',
                             count, count=count), 'success')
                return redirect(return_url)
        else:
            flash_errors(form, message='Failed to delete record. %(error)s')

        return redirect(return_url)


class ItemView(ModelView):
    # column_list = (
    #     'name', "category_of_items", "price", "image_url",
    # )
    #
    # form_columns = (
    #     'name', "category_of_items", "price", "image_url",
    # )
    #
    # column_sortable_list = (
    #     'name', ("name", "price"), "image_url",
    # )

    @expose('/new/', methods=('GET', 'POST'))
    def create_view(self):
        """
            Create model view
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_create:
            return redirect(return_url)

        form = self.create_form()
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_create_rules, form=form)

        if self.validate_form(form):
            # in versions 1.1.0 and before, this returns a boolean
            # in later versions, this is the model itself
            model = self.create_model(form)

            if model:
                # RabbitMQ
                concat = ProductConnection(connection)
                concat.AddProduct(model)

                # model.id model.name changed
                flash(gettext('Record was successfully created.'), 'success')
                if '_add_another' in request.form:
                    return redirect(request.url)
                elif '_continue_editing' in request.form:
                    # if we have a valid model, try to go to the edit view
                    if model is not True:
                        url = self.get_url('.edit_view', id=self.get_pk_value(model), url=return_url)
                    else:
                        url = return_url
                    return redirect(url)
                else:
                    # save button

                    return redirect(self.get_save_return_url(model, is_created=True))

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_create_rules)

        if self.create_modal and request.args.get('modal'):
            template = self.create_modal_template
        else:
            template = self.create_template

        return self.render(template,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @expose('/edit/', methods=('GET', 'POST'))
    def edit_view(self):
        """
            Edit model view
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_edit:
            return redirect(return_url)

        id = get_mdict_item_or_list(request.args, 'id')
        if id is None:
            return redirect(return_url)

        model = self.get_one(id)

        if model is None:
            flash(gettext('Record does not exist.'), 'error')
            return redirect(return_url)

        form = self.edit_form(obj=model)
        if not hasattr(form, '_validated_ruleset') or not form._validated_ruleset:
            self._validate_form_instance(ruleset=self._form_edit_rules, form=form)

        if self.validate_form(form):
            if self.update_model(form, model):

                # RabbitMQ
                concat = ProductConnection(connection)
                concat.ChangeProduct(model, form)

                flash(gettext('Record was successfully saved.'), 'success')
                if '_add_another' in request.form:
                    return redirect(self.get_url('.create_view', url=return_url))
                elif '_continue_editing' in request.form:
                    return redirect(self.get_url('.edit_view', id=self.get_pk_value(model)))
                else:
                    # save button
                    return redirect(self.get_save_return_url(model, is_created=False))

        if request.method == 'GET' or form.errors:
            self.on_form_prefill(form, id)

        form_opts = FormOpts(widget_args=self.form_widget_args,
                             form_rules=self._form_edit_rules)

        if self.edit_modal and request.args.get('modal'):
            template = self.edit_modal_template
        else:
            template = self.edit_template

        return self.render(template,
                           model=model,
                           form=form,
                           form_opts=form_opts,
                           return_url=return_url)

    @expose('/delete/', methods=('POST',))
    def delete_view(self):
        """
            Delete model view. Only POST method is allowed.
        """
        return_url = get_redirect_target() or self.get_url('.index_view')

        if not self.can_delete:
            return redirect(return_url)

        form = self.delete_form()

        if self.validate_form(form):
            # id is InputRequired()
            id = form.id.data

            model = self.get_one(id)

            if model is None:
                flash(gettext('Record does not exist.'), 'error')
                return redirect(return_url)

            # RabbitMQ
            concat = ProductConnection(connection)
            concat.DeleteProduct(model)

            # message is flashed from within delete_model if it fails
            if self.delete_model(model):
                count = 1
                flash(
                    ngettext('Record was successfully deleted.',
                             '%(count)s records were successfully deleted.',
                             count, count=count), 'success')
                return redirect(return_url)
        else:
            flash_errors(form, message='Failed to delete record. %(error)s')

        return redirect(return_url)


class Items(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(20), unique=False, nullable=False)
    price = db.Column(db.String(120), unique=False, nullable=False)
    image_url = db.Column(db.String(200), nullable=False, default='default.jpg')
    item_category = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=True)
    category_of_items = db.relationship('Category')

    def toDict(self):
        return {'id': self.id, 'name': self.name, 'price': self.price, 'image_url': self.image_url,
                'item_category': self.item_category}


admin = Admin(app, name="Каталог", template_mode="bootstrap3")
admin.add_view(CategoryView(Category, db.session, name="Категории"))
admin.add_view(ItemView(Items, db.session, name="Товары"))


db.create_all()


@app.before_request
def checkToken():
    if request.full_path == ('/admin/?'):
        auth = ''
        if request.headers['Authorization']:
            auth = request.headers['Authorization']
        token = jwt.decode(auth, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        if token['role_id'] != 1:
            return