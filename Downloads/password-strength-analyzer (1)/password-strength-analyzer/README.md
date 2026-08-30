# Password Strength Analyzer

Minor Project (BCA) — Khwaja Moinuddin Chishti Language University, Lucknow
Author: **Abdullah Razi** | Guide: **Dr. Raza Abbas Haidri**

A Flask web app jo password ki strength ko real-time analyze karta hai —
length, character mix, entropy, common patterns (sequential/repeated/keyboard-walk)
aur ek common-password dictionary check ke basis par. Password kabhi bhi
server par store ya log nahi hota, sirf live analyze hota hai.

**Live demo:** deployed on Vercel (see repository for the current link)
**Repository:** https://github.com/abdullahrazib-1630-dotcom/password-strength-analyzer

## Features (Synopsis ke 12 modules ke hisaab se)

1. User Interface — clean single-page UI
2. Password Input — show/hide toggle
3. Password Validation — length & allowed characters
4. Strength Analysis — length, upper/lower/digit/special mix
5. Pattern Detection — sequential, repeated, keyboard-walk patterns
6. Dictionary Check — common/leaked password list
7. Entropy Calculation — bits of entropy + estimated crack time
8. Suggestion Engine — real-time improvement tips
9. Password Generator — cryptographically secure random password
10. Result Display — animated strength dial + stats
11. Security Guidelines — best-practice tips section
12. Help — this README + in-page copy

## Run locally

```bash
# 1. create a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. install dependencies
pip install -r requirements.txt

# 3. run the app
python app.py
```

App will start at **http://127.0.0.1:5000**

## Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit: Password Strength Analyzer"
git branch -M main
git remote add origin https://github.com/abdullahrazib-1630-dotcom/password-strength-analyzer.git
git push -u origin main
```

## Deploy on Vercel

1. https://vercel.com par GitHub se sign in karo.
2. **Add New → Project** → apna `password-strength-analyzer` repo import karo.
3. Vercel `vercel.json` ko automatically detect kar lega (Python/Flask runtime).
4. **Deploy** click karo — 1-2 min me live URL mil jayega (e.g. `password-strength-analyzer.vercel.app`).
5. Jab bhi GitHub repo me naya commit push karoge, Vercel automatically redeploy kar dega.

## Project structure

```
password-strength-analyzer/
├── app.py                  # Flask backend (all analysis logic)
├── requirements.txt
├── vercel.json              # Vercel deployment config
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/script.js
└── README.md
```

## Tech stack

- Backend: Python 3, Flask
- Frontend: HTML5, CSS3, vanilla JavaScript (no frameworks)
- Deployment: Vercel (serverless, auto-deploys from GitHub)

## Future enhancements (from synopsis conclusion)

- AI-based password risk prediction
- Real breach-database check (e.g. Have I Been Pwned API)
- Multi-language support
- Direct integration with authentication systems
