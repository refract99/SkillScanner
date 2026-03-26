# Dev Deployment Summary

**Deployed:** 2026-03-26 21:23:38 UTC
**Site:** SkillScanner
**Admin:** (not set)

## Production URLs

| Service | URL |
|---------|-----|
| App | https://skillscanner-seven.vercel.app |
| Vercel Deployments | https://vercel.com/stevebrodson-2428s-projects/skillscanner/deployments |
| GitHub Repo | https://github.com/refract99/SkillScanner |
| Convex Cloud | https://bright-salmon.convex.cloud |
| Convex HTTP Actions | https://bright-salmon.convex.site |
| Clerk Frontend API | https://valid-basic.clerk.accounts.dev |
| Convex Dashboard | https://dashboard.convex.dev |
| Clerk Dashboard | https://dashboard.clerk.com |

## Completed Steps

- [x] GitHub repo configured
- [x] Vercel project created and linked
- [x] Vercel env vars set (16 variables)
- [x] Deployed to Vercel

## Skipped / Deferred

- [ ] Clerk production (run /deploy-to-prod)
- [ ] Google OAuth (run /deploy-to-prod)
- [ ] Stripe billing (run /deploy-to-prod)

## Environment Variables Set

## Webhook

- Endpoint: `(not configured)`
- Events: user.created, user.updated, user.deleted, paymentAttempt.updated

## Ongoing Deployments

Future deployments happen automatically when you push to main:
```bash
git push origin main
```
Vercel auto-deploys on push, including Convex function updates (via `vercel.json` buildCommand).

## Upgrade to Production Clerk

When you have a custom domain and are ready to remove the Clerk dev badge, run:
```bash
/deploy-to-prod
```

This will walk you through:
- Creating a Clerk production instance (requires a custom domain you own)
- Swapping to production Clerk keys (pk_live_/sk_live_)
- Setting up Google OAuth with your own credentials
- Configuring Stripe billing via Clerk

## Optional Next Steps

1. **Custom Domain**: Vercel Dashboard → Settings → Domains → Add your domain

## Verify Your Deployment

1. Visit your production URL: https://skillscanner-seven.vercel.app
2. Create a test account
3. Check Convex Dashboard → Production → Data → users table
4. User should appear (confirms webhook is working)
