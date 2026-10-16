use FixMyStreet::TestMech;

# SECURITY REGRESSION TEST (cross-tenant privilege manipulation).
#
# POST /admin/users (Admin::Users::index, the "staff list" bulk action form)
# takes arbitrary uid[] values and looks them up with a GLOBAL user search
# (FixMyStreet::DB->resultset("User")->search({ id => \@uids })) with no
# restriction to the acting staff member's own body, no dedicated permission
# check and no CSRF token check (unlike e.g. the edit() action).
#
# This test asserts that a council staff member who only holds the
# 'user_edit' permission on their own body MUST NOT be able to:
#   1. remove the staff status of an account belonging to a different
#      council (destructive cross-tenant write), nor
#   2. assign to their own account a Role belonging to a different council
#      (cross-tenant privilege escalation).
#
# On a vulnerable application these assertions FAIL because the writes are
# performed; the future fix should make this test pass.

my $mech = FixMyStreet::TestMech->new;

# Two distinct tenants on the same platform.
my $oxfordshire = $mech->create_body_ok( 2237, 'Oxfordshire County Council',
    { cobrand => 'oxfordshire' } );
my $haringey = $mech->create_body_ok( 2509, 'Haringey Borough Council' );

# Attacker: ordinary Oxfordshire staff, only permission is user_edit.
my $attacker = $mech->create_user_ok( 'oxford-staff@example.org',
    name => 'Oxfordshire Staff', from_body => $oxfordshire->id );
$attacker->user_body_permissions->create( {
    body            => $oxfordshire,
    permission_type => 'user_edit',
} );

# Victim: staff member of a *different* council (Haringey), with a body
# permission and a role granting moderate/report_edit on Haringey.
my $victim = $mech->create_user_ok( 'haringey-staff@example.org',
    name => 'Haringey Staff', from_body => $haringey->id );
$victim->user_body_permissions->create( {
    body            => $haringey,
    permission_type => 'moderate',
} );
my $haringey_role = $victim->roles->create( {
    body        => $haringey,
    name        => 'Haringey Moderators',
    permissions => [ 'moderate', 'report_edit' ],
} );
$victim->add_to_roles($haringey_role);

FixMyStreet::override_config {
    ALLOWED_COBRANDS => ['oxfordshire'],
    MAPIT_URL        => 'http://mapit.uk/',
}, sub {
    $mech->log_in_ok( $attacker->email );

    subtest 'cross-tenant remove-staff via POST /admin/users is refused' => sub {
        # Deliberately no CSRF token, exactly like a forged cross-site
        # request (or a plain curl) targeting a logged-in staff member.
        $mech->post( '/admin/users', {
            uid           => $victim->id,
            'remove-staff' => 'remove-staff',
        } );
        diag 'POST /admin/users (remove-staff) returned HTTP ' . $mech->status;

        $victim->discard_changes;
        is $victim->from_body ? $victim->from_body->id : undef, $haringey->id,
            'Haringey staff account must still belong to Haringey';
        is $victim->email_verified, 1,
            'Haringey staff account must still have a verified email';
        is $victim->user_body_permissions->count, 1,
            'Haringey staff account must keep its body permissions';
        is $victim->user_roles->count, 1,
            'Haringey staff account must keep its roles';
    };

    subtest 'assigning a foreign body role via POST /admin/users is refused' => sub {
        # Self-escalation: attacker asks for a Role that belongs to the
        # Haringey body, not their own Oxfordshire body.
        $mech->post( '/admin/users', {
            uid   => $attacker->id,
            roles => $haringey_role->id,
        } );
        diag 'POST /admin/users (roles) returned HTTP ' . $mech->status;

        $attacker->discard_changes;
        my $foreign = $attacker->user_roles->search(
            { role_id => $haringey_role->id } )->count;
        is $foreign, 0,
            'Oxfordshire staff must not be able to self-assign a Haringey role';
        ok !$attacker->has_permission_to( 'moderate', $haringey->id ),
            'Oxfordshire staff must not hold Haringey permissions via a foreign role';
    };

    $mech->log_out_ok;
};

done_testing;
