from django.shortcuts import render,redirect
from . import models
from . import forms
from django.core.mail import send_mail
from random import Random
import hashlib
# Create your views here.
def random_string(length=8):
    string= ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars)-1
    random = Random()
    for i in range(30):
        string += chars[random.randit(0,length)]
    return string
def hash_code(password):
    h = hashlib.sha256()
    h.update(password.encode('utf-8'))
    return h.hexdigest()

def index(request):
    return render(request, 'practices/index.html')


def login(request):
    if request.session.get('is_login',None):
        return redirect('/')
    if request.method == "POST":
        form = forms.UserForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            username = username.strip()
            try:
                user = models.User.objects.get(name=username)
                if user.password == hash_code(password):
                    request.session['is_login'] = True
                    request.session['user_id'] = user.id
                    request.session['user_name'] = user.name
                    if form.cleaned_data['remember'] == True:
                        request.session.set_expiry(30000)
                    return redirect('/')
                else:
                    message = "错误的密码。"
            except:
                message = "用户名不存在。"
        return render(request, 'practices/login.html', locals())
    form = forms.UserForm()
    return render(request, 'practices/login.html', {'form':form})


def register(request):
    if request.session.get('is_login', None):
       return redirect('/')
    if request.method == 'POST':
        form = forms.RegisterForm(request.POST)
        message = "信息无效"
        if form.is_valid():
            username = form.cleaned_data['username']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']
            email = form.cleaned_data['email']
            if password1 != password2:
                message = "两次输入的密码必须相同"
                return render(request, 'practices/register.html', locals())
            else:
                same_username = models.User.objects.filter(name=username)
                if same_username:
                    message = "用户名已存在"
                    return render(request, 'practices/register.html', locals())
                same_email = models.User.objects.filter(email=email)
                if same_email:
                    message = "邮箱已存在"
                    return render(request, 'practices/register.html', locals())
                new_user = models.User.objects.create()
                new_user.name = username
                new_user.password = hash_code(password2)
                new_user.email = email
                new_user.save()
                return redirect('/login/')
    form = forms.RegisterForm()
    return render(request, 'practices/register.html',locals())


def logout(request):
    if not request.session.get('is_login' ,None):
        return redirect('/')

    request.session.flush()

    return redirect('/')

def change(request):
    if not request.session.get('is_login', None):
       return redirect('/')
    if request.method == 'POST':
        form = forms.ChangeForm(request.POST)
        message = "信息无效"
        if form.is_valid():
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']
            email = form.cleaned_data ['email']
            if password1 != password2:
                message = "两次输入的密码必须相同"
                return render(request, 'practices/change.html', locals())
            same_email = models.User.objects.filter(email=email)
            if same_email:
                message = "邮箱已存在"
                return render(request, 'practices/change.html', locals())
            changed_user = request.session.get('user_id')
            user = models.User.objects.get(id=changed_user)
            user.password = hash_code(password2)
            user.email = email
            user.save()
            request.session.flush()
            return redirect('/')
    form =forms.ChangeForm()
    return render(request, 'practices/change.html', locals())
