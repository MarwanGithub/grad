from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, get_user_model, get_backends
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.core.files.base import ContentFile
import random
import pyotp
import qrcode
from io import BytesIO
from .models import CustomUser, Candidate, Voter
from .forms import CustomUserCreationForm, LoginForm


def home(request):
    categories = ["President", "Vice President", "Secretary"]
    return render(request, "voting/home.html", {"categories": categories})



def register(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)

        if form.is_valid():
            user = form.save(commit=False)  # ✅ إنشاء المستخدم بدون حفظه مباشرةً
            user.is_verified = False
            user.otp_secret = pyotp.random_base32()  # ✅ إنشاء كود OTP Secret
            user.save()  # 🔹 يجب الحفظ أولًا للحصول على user.id

            # ✅ إنشاء كود QR بعد حفظ المستخدم
            totp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(user.email, issuer_name="E-Voting System")
            qr = qrcode.make(totp_uri)
            buffer = BytesIO()
            qr.save(buffer, format="PNG")

            # ✅ حفظ QR Code في `qr_code` الحقل في `CustomUser`
            user.qr_code.save(f"otp_qr_{user.id}.png", ContentFile(buffer.getvalue()), save=True)

            # ✅ تسجيل دخول المستخدم مباشرةً
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # ✅ حفظ بيانات الجلسة للتحقق عبر Gmail
            request.session["user_id"] = user.id
            request.session["email"] = user.email

            messages.success(request, "✅ Registration successful! Scan the QR code with Google Authenticator and verify via OTP sent to your email.")
            return redirect("send_otp")  # 🔹 إرسال المستخدم إلى التحقق عبر Gmail

        else:
            messages.error(request, "❌ Registration failed. Please check the form.")

    else:
        form = CustomUserCreationForm()

    return render(request, "voting/register.html", {"form": form})



User = get_user_model()


def login_view(request):
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)

        print("📌 بيانات الإدخال:", request.POST)  # طباعة البيانات المدخلة
        
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]

            user = authenticate(request, username=username, password=password)

            if user:
                login(request, user)
                messages.success(request, "✅ تسجيل دخول ناجح!")
                return redirect("vote")
            else:
                messages.error(request, "❌ بيانات الدخول غير صحيحة!")

        else:
            print("❌ بيانات الفورم غير صحيحة!")
            print("🔴 أخطاء الفورم:", form.errors)  # طباعة الأخطاء الفعلية

    else:
        form = LoginForm()
    
    return render(request, "voting/login.html", {"form": form})



def verify_totp(request, candidate_id):
    user_id = request.session.get("pending_user_id")

    if not user_id:
        messages.error(request, "❌ Session expired. Please log in again.")
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)
    candidate = get_object_or_404(Candidate, id=candidate_id)  # جلب بيانات المرشح

    if request.method == "POST":
        otp_code = request.POST.get("otp")
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(otp_code):
            # تسجيل التصويت للمستخدم بعد نجاح التحقق
            user.voted_candidates.add(candidate)  
            user.save()

            del request.session["pending_user_id"]  # إزالة المتغير من الجلسة بعد التحقق

            messages.success(request, f"✅ Your vote for {candidate.name} has been recorded!")
            return redirect("home")  # إعادة التوجيه إلى الصفحة الرئيسية بعد التصويت
        else:
            del request.session["pending_user_id"]  # حذف بيانات الجلسة بعد محاولة فاشلة
            messages.error(request, "❌ Invalid OTP. Please log in again to receive a new code.")
            return redirect("login")  # ⏭ إعادة تسجيل الدخول للحصول على كود جديد

    return render(request, "voting/verify_totp.html", {"candidate": candidate})






@login_required(login_url="/login/")
def logout_view(request):
    logout(request)
    messages.success(request, "✅ Logout successful!")
    return redirect("home")

def send_otp(request):
    # Retrieve email from session
    email = request.session.get("email")
    
    # If email is not in session, redirect to login
    if not email:
        messages.error(request, "❌ Email not available, please log in.")
        return redirect("login")

    # Generate a new OTP code
    otp_code = str(random.randint(100000, 999999))

    # Store OTP in session
    request.session["otp_code"] = otp_code

    # Send OTP via email
    send_mail(
        "Your OTP Code",
        f"Your OTP code is: {otp_code}",
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    messages.success(request, "✅ OTP has been sent to your email.")
    return redirect("verify_otp")



def verify_otp(request): 
    email = request.session.get("email")
    user_id = request.session.get("user_id")

    if not email or not user_id:
        messages.error(request, "❌ Session expired. Please log in again.")
        return redirect("login")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        entered_gmail_otp = request.POST.get("gmail_otp")
        entered_authenticator_otp = request.POST.get("authenticator_otp")
        stored_gmail_otp = request.session.get("otp_code")

        # ✅ التحقق من OTP المرسل عبر Gmail
        if entered_gmail_otp != stored_gmail_otp:
            del request.session["otp_code"]  # 🛑 حذف الكود بعد أول محاولة
            messages.error(request, "❌ Incorrect OTP from email. A new OTP has been sent.")
            return redirect("resend_otp")  # ⏭ إعادة إرسال كود جديد

        # ✅ التحقق من OTP عبر Google Authenticator
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(entered_authenticator_otp):
            messages.error(request, "❌ Incorrect OTP from Google Authenticator. Please try again.")
            return redirect("verify_otp")

        # ✅ تفعيل الحساب بعد اجتياز التحققين
        user.is_verified = True
        user.save()

        # ✅ تسجيل دخول المستخدم تلقائيًا مع تحديد `backend`
        backend = settings.AUTHENTICATION_BACKENDS[0]  # اختيار أول backend (EmailAuthBackend)
        login(request, user, backend=backend)

        # ✅ مسح بيانات الجلسة
        del request.session["otp_code"]
        del request.session["user_id"]
        del request.session["email"]

        messages.success(request, "✅ Verification successful! You are now logged in.")
        return redirect("home")

    return render(request, "voting/verify_otp.html", {"email": email})



    
# Resend OTP
def resend_otp(request):
    email = request.session.get("email")

    if not email:
        messages.error(request, "❌ Email not found.")
        return redirect("send_otp")

    otp_code = str(random.randint(100000, 999999))
    request.session["otp_code"] = otp_code

    send_mail(
        "New OTP Code",
        f"Your new OTP code is: {otp_code}",
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

    messages.success(request, "✅ A new OTP has been sent to your email.")
    return redirect("verify_otp")

# Change email
def change_email(request):
    request.session.pop("email", None)
    request.session.pop("otp_code", None)
    messages.info(request, "✉️ Please enter a new email.")
    return redirect("send_otp")


@login_required(login_url="/login/")
def vote_home(request):
    categories = ["President", "Vice President", "Secretary"]
    return render(request, "voting/vote_home.html", {"categories": categories})

CANDIDATES = {
    "President": [
        {"id": 1, "name": "Ahmed", "image": "/media/ahmed.jpg", "description": "description", "votes": 0},
        {"id": 2, "name": "Sara", "image": "/media/sara.jpg", "description": "description", "votes": 0},
    ],
    "Vice President": [
        {"id": 3, "name": "Mohamed", "image": "/media/mohamed.jpg", "description": "description", "votes": 0},
        {"id": 4, "name": "Nora", "image": "/media/nora.jpg", "description": "description", "votes": 0},
    ],
    "Secretary": [
        {"id": 5, "name": "Omar", "image": "/media/omar.jpg", "description": "description", "votes": 0},
        {"id": 6, "name": "Laila", "image": "/media/laila.jpg", "description": "description", "votes": 0},
    ],
}



@login_required(login_url="/login/")
def vote_category(request, category):
    allowed_categories = ["President", "Vice President", "Secretary"]

    if category not in allowed_categories:
        messages.error(request, "❌ Invalid category selected.")
        return redirect("vote_home")

    candidates = CANDIDATES.get(category, [])

    # تعديل الصور لجعلها مسارات كاملة
    for candidate in candidates:
        candidate["image_url"] = settings.MEDIA_URL + candidate["image"]

    if request.method == "POST":
        email = request.session.get("email")
        if not email:
           messages.error(request, "❌ You must be logged in to vote.")
           return redirect("login")

        candidate_id = request.POST.get("candidate_id")
        if not candidate_id:
            messages.error(request, "❌ Please select a candidate before voting.")
            return redirect("vote_category", category=category)

        candidate_id = int(candidate_id)
        candidate = next((c for c in candidates if c["id"] == candidate_id), None)

        if not candidate:
            messages.error(request, "❌ Invalid candidate selected.")
            return redirect("vote_category", category=category)

        candidate["votes"] += 1
        messages.success(request, f"✅ Voting successful for {candidate['name']}!")
        return redirect("vote_home")

    return render(request, "voting/vote_category.html", {"category": category, "candidates": candidates})




 
def get_candidate_details(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)

    # تحقق إذا كان الطلب AJAX أو عادي
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'name': candidate.name,
            'image_url': candidate.image.url,  
            'description': candidate.description,
        })

    return render(request, "voting/candidate_details.html", {"candidate": candidate})





def vote_candidate(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)  # جلب بيانات المرشح
    return render(request, "voting/vote_candidate.html", {"candidate": candidate})

from django.shortcuts import render, get_object_or_404, redirect
from .models import Candidate

def confirm_vote(request, candidate_id):
    candidate = get_object_or_404(Candidate, id=candidate_id)
    
    if request.method == "POST":
        candidate.votes += 1
        candidate.save()

        return render(request, "voting/vote_success.html", {"candidate": candidate})

    return redirect("vote_home")
