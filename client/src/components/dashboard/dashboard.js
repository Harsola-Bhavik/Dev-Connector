import React, { useEffect } from "react";
import { Link } from "react-router-dom";
import PropTypes from "prop-types";
import { connect } from "react-redux";
import { getCurrentProfile, deleteAccount } from "../../actions/profile";
import DashboardActions from "./DashboardActions";
import Experience from "./Experience";
import Education from "./Education";

const Dashboard = ({
  getCurrentProfile,
  deleteAccount,
  auth: { user },
  profile: { profile, loading }
}) => {
  useEffect(() => {
    getCurrentProfile();
  }, [getCurrentProfile]);

  return loading && profile === null ? (
    <div>Loading...</div>
  ) : (
    <section className="container animated-fade-in">
      <div className="dashboard-banner">
        <h1 className="large">Dashboard</h1>
        <p className="lead">
          <i className="fas fa-user" /> Welcome, {user && user.name}
        </p>
      </div>

      {profile !== null ? (
        <>
          <DashboardActions />
          <div className="dashboard-data-grid">
            <Experience experience={profile.experience} />
            <Education education={profile.education} />
          </div>

          <div className="danger-zone my-2">
            <h3>Danger Zone</h3>
            <p>Once you delete your account, there is no going back. Please be certain.</p>
            <button className="btn btn-danger" onClick={() => deleteAccount()}>
              <i className="fas fa-user-minus" /> Delete My Account
            </button>
          </div>
        </>
      ) : (
        <div className="empty-state-card">
          <i className="fas fa-user-circle fa-4x text-primary" style={{ marginBottom: '1rem' }}></i>
          <h3>Profile Not Found</h3>
          <p>You have not yet setup a profile, please add some info to get started!</p>
          <Link to="/create-profile" className="btn btn-primary my-1">
            Create Profile
          </Link>
        </div>
      )}
    </section>
  );
};

Dashboard.propTypes = {
  getCurrentProfile: PropTypes.func.isRequired,
  deleteAccount: PropTypes.func.isRequired,
  auth: PropTypes.object.isRequired,
  profile: PropTypes.object.isRequired
};

const mapStateToProps = (state) => ({
  auth: state.auth,
  profile: state.profile
});

export default connect(mapStateToProps, { getCurrentProfile, deleteAccount })(
  Dashboard
);
