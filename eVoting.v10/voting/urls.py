from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import vote_home

from .views import (
    home, vote_home, register, login_view, logout_view,
    send_otp, verify_otp, change_email, resend_otp,
    vote_category, get_candidate_details, verify_totp,vote_candidate
)

urlpatterns = [
    # الصفحات الرئيسية
    path("", home, name="home"),
    path("vote/", vote_home, name="vote"),

    # إدارة الحساب
    path("register/", register, name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    
    # OTP والتحقق
    path("send-otp/", send_otp, name="send_otp"),
    path("verify-otp/", verify_otp, name="verify_otp"),
    path("change_email/", change_email, name="change_email"),
    path("resend-otp/", resend_otp, name="resend_otp"),

    # التصويت
    path("vote/<str:category>/", vote_category, name="vote_category"),
    path("candidate/<int:candidate_id>/", get_candidate_details, name="get_candidate_details"),
    path("verify_totp/<int:candidate_id>/", verify_totp, name="verify_totp"),
    path("vote/<int:candidate_id>/", vote_candidate, name="vote_candidate")
 


]

# دعم ملفات الميديا (مثل صور المرشحين)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
