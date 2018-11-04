from django import forms
from captcha.fields import CaptchaField


class UserForm(forms.Form):
    username = forms.CharField(label="用户名", max_length = 16, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label="密码" , max_length= 256, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    captcha = CaptchaField(label='验证码', error_messages={"invalid": u"验证码错误"})
    remember = forms.BooleanField(label='记住密码', required=False)

class RegisterForm(forms.Form):
    username = forms.CharField(label="用户名", max_length=16, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password1 = forms.CharField(label="密码", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    password2 = forms.CharField(label="确认密码", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(label="邮箱地址", widget=forms.EmailInput(attrs={'class': 'form-control'}))
    captcha = CaptchaField(label='验证码')

class ChangeForm(forms.Form):
    password1 = forms.CharField(label="密码", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    password2 = forms.CharField(label="确认密码", max_length=256, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(label="邮箱地址", widget=forms.EmailInput(attrs={'class': 'form-control'}))
    captcha = CaptchaField(label='验证码')